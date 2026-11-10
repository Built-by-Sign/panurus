/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package token

import (
	"context"
	"errors"
	"testing"

	"github.com/LFDT-Panurus/panurus/token/driver/mock"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/stretchr/testify/require"
)

func newCachedTokensService(ts *mock.TokensService) *TokensService {
	return &TokensService{ts: ts, deobfuscated: newDeobfuscationCache()}
}

func TestDeobfuscateCachesByContent(t *testing.T) {
	ts := &mock.TokensService{}
	ts.DeobfuscateReturns(&token.Token{Owner: []byte("alice"), Type: "USD", Quantity: "0x0a"}, Identity("issuer"), []Identity{Identity("alice")}, "fmt", nil)
	s := newCachedTokensService(ts)
	ctx := context.Background()

	tok, issuer, recipients, format, err := s.Deobfuscate(ctx, []byte("out"), []byte("meta"))
	require.NoError(t, err)
	// mutating what the caller got back must not leak into the next hit
	tok.Owner[0] = 'X'
	issuer[0] = 'X'
	recipients[0][0] = 'X'
	recipients[0] = Identity("bob")

	tok2, issuer2, recipients2, format2, err := s.Deobfuscate(ctx, []byte("out"), []byte("meta"))
	require.NoError(t, err)
	require.Equal(t, 1, ts.DeobfuscateCallCount())
	require.Equal(t, token.Token{Owner: []byte("alice"), Type: "USD", Quantity: "0x0a"}, *tok2)
	require.Equal(t, Identity("issuer"), issuer2)
	require.Equal(t, []Identity{Identity("alice")}, recipients2)
	require.Equal(t, token.Format("fmt"), format)
	require.Equal(t, format, format2)

	// a different split of the same bytes is a different key
	_, _, _, _, err = s.Deobfuscate(ctx, []byte("ou"), []byte("tmeta"))
	require.NoError(t, err)
	require.Equal(t, 2, ts.DeobfuscateCallCount())
}

func TestDeobfuscateDoesNotCacheErrors(t *testing.T) {
	ts := &mock.TokensService{}
	ts.DeobfuscateReturns(nil, nil, nil, "", errors.New("bad opening"))
	s := newCachedTokensService(ts)

	for range 2 {
		_, _, _, _, err := s.Deobfuscate(context.Background(), []byte("out"), []byte("meta"))
		require.EqualError(t, err, "bad opening")
	}
	require.Equal(t, 2, ts.DeobfuscateCallCount())
}

func TestDeobfuscateWithoutCacheCallsThrough(t *testing.T) {
	ts := &mock.TokensService{}
	ts.DeobfuscateReturns(&token.Token{Type: "USD"}, nil, nil, "fmt", nil)
	s := &TokensService{ts: ts}

	for range 2 {
		_, _, _, _, err := s.Deobfuscate(context.Background(), []byte("out"), []byte("meta"))
		require.NoError(t, err)
	}
	require.Equal(t, 2, ts.DeobfuscateCallCount())
}
