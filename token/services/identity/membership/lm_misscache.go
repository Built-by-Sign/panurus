/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package membership

import (
	"os"
	"sync"
	"time"
)

// missCacheTTLEnv enables the miss cache with the given duration (e.g. "2s"). Perf-only:
// a node that never owns the looked-up identities (an auditor) otherwise queries the
// identity store on every lookup.
const missCacheTTLEnv = "PANURUS_PERF_LM_MISS_TTL"

const missCacheCap = 65536

// missCache remembers labels the identity store did not know, for a short TTL.
type missCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	until map[string]time.Time
}

func newMissCacheFromEnv() *missCache {
	ttl, err := time.ParseDuration(os.Getenv(missCacheTTLEnv))
	if err != nil || ttl <= 0 {
		return nil
	}

	return &missCache{ttl: ttl, until: map[string]time.Time{}}
}

func (c *missCache) hit(label string, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	return now.Before(c.until[label])
}

func (c *missCache) add(label string, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.until) >= missCacheCap {
		clear(c.until)
	}
	c.until[label] = now.Add(c.ttl)
}

func (c *missCache) reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.until)
}
