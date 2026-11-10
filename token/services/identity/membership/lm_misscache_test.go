/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package membership_test

import (
	"testing"

	"github.com/LFDT-Panurus/panurus/token/services/identity"
	idriver "github.com/LFDT-Panurus/panurus/token/services/identity/driver"
	"github.com/LFDT-Panurus/panurus/token/services/identity/membership"
	"github.com/LFDT-Panurus/panurus/token/services/identity/membership/mock"
	"github.com/LFDT-Panurus/panurus/token/services/logging"
	"github.com/LFDT-Panurus/panurus/token/services/storage"
	"github.com/stretchr/testify/require"
)

func newMissCacheMembership(t *testing.T) (*membership.LocalMembership, *mock.IdentityStoreService) {
	t.Helper()
	ip := &mock.IdentityProvider{}
	ip.BindReturns(nil)
	iss := &mock.IdentityStoreService{}
	iss.NotifierReturns(nil, storage.ErrNotSupported)
	iss.IteratorConfigurationsReturns(&mock.IdentityConfigurationIterator{}, nil)
	km := &mock.KeyManager{}
	km.EnrollmentIDReturns("e1")
	km.IdentityReturns(&idriver.IdentityDescriptor{Identity: []byte("id1"), AuditInfo: []byte("ai")}, nil)
	km.IdentityTypeReturns(identity.Type(99))
	kmp := &mock.KeyManagerProvider{}
	kmp.GetReturns(km, nil)
	lm := membership.NewLocalMembership(logging.MustGetLogger("test"), &mock.Config{}, []byte("netid"), &mock.SignerDeserializerManager{}, iss, "testType", false, ip, kmp)
	require.NoError(t, lm.Load(t.Context(), nil, nil))

	return lm, iss
}

func TestMissCacheSkipsStoreForRecentlyUnknownLabel(t *testing.T) {
	t.Setenv("PANURUS_PERF_LM_MISS_TTL", "1h")
	lm, iss := newMissCacheMembership(t)
	ctx := t.Context()

	for range 3 {
		_, err := lm.GetIdentityInfo(ctx, "ghost", nil)
		require.Error(t, err)
	}
	require.Equal(t, 1, iss.ConfigurationsByIDCallCount())

	// a registration invalidates the cache, so a configuration added meanwhile is found
	require.NoError(t, lm.RegisterIdentity(ctx, membership.IdentityConfiguration{ID: "other", URL: "/tmp/other", Type: "testType"}))
	iss.ConfigurationsByIDReturns([]idriver.IdentityConfiguration{{ID: "ghost", URL: "/tmp/ghost", Type: "testType"}}, nil)
	info, err := lm.GetIdentityInfo(ctx, "ghost", nil)
	require.NoError(t, err)
	require.Equal(t, "ghost", info.ID())
	require.Equal(t, 2, iss.ConfigurationsByIDCallCount())
}

func TestMissCacheExpires(t *testing.T) {
	t.Setenv("PANURUS_PERF_LM_MISS_TTL", "1ns")
	lm, iss := newMissCacheMembership(t)

	for range 2 {
		_, err := lm.GetIdentityInfo(t.Context(), "ghost", nil)
		require.Error(t, err)
	}
	require.Equal(t, 2, iss.ConfigurationsByIDCallCount())
}

func TestMissCacheDisabledByDefault(t *testing.T) {
	lm, iss := newMissCacheMembership(t)

	for range 2 {
		_, err := lm.GetIdentityInfo(t.Context(), "ghost", nil)
		require.Error(t, err)
	}
	require.Equal(t, 2, iss.ConfigurationsByIDCallCount())
}
