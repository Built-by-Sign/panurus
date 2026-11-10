/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package token

import (
	"context"
	"slices"
	"strconv"
	"sync"

	"github.com/LFDT-Panurus/panurus/token/driver"
	"github.com/LFDT-Panurus/panurus/token/token"
)

// deobfuscationCacheSize bounds the number of cached deobfuscated outputs; the cache is
// cleared when it fills up.
const deobfuscationCacheSize = 8192

// TokensService models the token service
type TokensService struct {
	ts  driver.TokensService
	tus driver.TokensUpgradeService
	// deobfuscated caches successful Deobfuscate results by (output, metadata) content.
	// The same request is deobfuscated by several consumers (transaction record, token
	// cache, transaction outputs), each from its own Request instance. Nil disables it.
	deobfuscated *deobfuscationCache
}

type deobfuscated struct {
	tok        token.Token
	issuer     Identity
	recipients []Identity
	format     token.Format
}

type deobfuscationCache struct {
	mu      sync.RWMutex
	entries map[string]*deobfuscated
}

func newDeobfuscationCache() *deobfuscationCache {
	return &deobfuscationCache{entries: make(map[string]*deobfuscated)}
}

// Deobfuscate processes the passed output and metadata to derive a token.Token, its issuer (if any), and its token format
func (t *TokensService) Deobfuscate(ctx context.Context, output []byte, outputMetadata []byte) (*token.Token, Identity, []Identity, token.Format, error) {
	c := t.deobfuscated
	if c == nil {
		return t.ts.Deobfuscate(ctx, output, outputMetadata)
	}
	key := strconv.Itoa(len(output)) + ":" + string(output) + string(outputMetadata)
	c.mu.RLock()
	hit := c.entries[key]
	c.mu.RUnlock()
	if hit == nil {
		tok, issuer, recipients, format, err := t.ts.Deobfuscate(ctx, output, outputMetadata)
		if err != nil {
			return nil, nil, nil, "", err
		}
		hit = &deobfuscated{tok: *tok, issuer: issuer, recipients: recipients, format: format}
		c.mu.Lock()
		if len(c.entries) >= deobfuscationCacheSize {
			clear(c.entries)
		}
		c.entries[key] = hit
		c.mu.Unlock()
	}
	tok := hit.tok
	tok.Owner = slices.Clone(tok.Owner)

	return &tok, slices.Clone(hit.issuer), cloneIdentities(hit.recipients), hit.format, nil
}

func cloneIdentities(ids []Identity) []Identity {
	if ids == nil {
		return nil
	}
	out := make([]Identity, len(ids))
	for i, id := range ids {
		out[i] = slices.Clone(id)
	}

	return out
}

// NewUpgradeChallenge generates a new upgrade challenge
func (t *TokensService) NewUpgradeChallenge() ([]byte, error) {
	return t.tus.NewUpgradeChallenge()
}

// GenUpgradeProof generates an upgrade proof for the given challenge and tokens
func (t *TokensService) GenUpgradeProof(ctx context.Context, id []byte, tokens []token.LedgerToken) ([]byte, error) {
	return t.tus.GenUpgradeProof(ctx, id, tokens, nil)
}

// SupportedTokenFormats returns the supported token formats
func (t *TokensService) SupportedTokenFormats() []token.Format {
	return t.ts.SupportedTokenFormats()
}
