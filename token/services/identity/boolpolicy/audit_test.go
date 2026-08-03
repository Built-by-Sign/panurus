/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package boolpolicy

import (
	"testing"

	"github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/services/identity"
	"github.com/LFDT-Panurus/panurus/token/services/identity/deserializer"
	"github.com/LFDT-Panurus/panurus/token/services/identity/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newX509Member returns a typed x509 member identity and its audit info bytes.
func newX509Member(t *testing.T, name, eid string) ([]byte, []byte) {
	t.Helper()
	member, err := identity.WrapWithType(x509.IdentityType, []byte(name))
	require.NoError(t, err)
	auditInfo, err := (&x509.AuditInfo{EID: eid, RH: []byte("rh-" + eid)}).Bytes()
	require.NoError(t, err)

	return member, auditInfo
}

// newPolicyIdentity wraps the members into a typed policy identity and the
// matching composite audit info blob.
func newPolicyIdentity(t *testing.T, members [][]byte, auditInfos [][]byte) (token.Identity, []byte) {
	t.Helper()
	inner, err := (&PolicyIdentity{Policy: "$0 OR $1", Identities: members}).Serialize()
	require.NoError(t, err)
	policyID, err := identity.WrapWithType(Policy, inner)
	require.NoError(t, err)
	wrapped, err := WrapAuditInfo(auditInfos)
	require.NoError(t, err)

	return policyID, wrapped
}

// newEIDRHDeserializer mirrors the driver wiring: x509 plus a recursive
// boolpolicy audit-info deserializer.
func newEIDRHDeserializer() *deserializer.EIDRHDeserializer {
	d := deserializer.NewEIDRHDeserializer()
	d.AddDeserializer(x509.IdentityType, &x509.AuditInfoDeserializer{})
	d.AddDeserializer(Policy, NewAuditInfoDeserializer(d))

	return d
}

func TestPolicyEnrollmentIDCommonMembers(t *testing.T) {
	m0, ai0 := newX509Member(t, "cert-zero", "wallet-42")
	m1, ai1 := newX509Member(t, "cert-one", "wallet-42")
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0, m1}, [][]byte{ai0, ai1})

	eid, rh, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "wallet-42", eid)
	assert.Equal(t, "", rh)
}

func TestPolicyEnrollmentIDSingleMember(t *testing.T) {
	m0, ai0 := newX509Member(t, "cert-zero", "wallet-7")
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0}, [][]byte{ai0})

	eid, _, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "wallet-7", eid)
}

func TestPolicyEnrollmentIDConflictingMembers(t *testing.T) {
	m0, ai0 := newX509Member(t, "cert-zero", "wallet-42")
	m1, ai1 := newX509Member(t, "cert-one", "wallet-43")
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0, m1}, [][]byte{ai0, ai1})

	eid, _, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "", eid)
}

func TestPolicyEnrollmentIDEmptyMemberEID(t *testing.T) {
	m0, ai0 := newX509Member(t, "cert-zero", "")
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0}, [][]byte{ai0})

	eid, _, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "", eid)
}

func TestPolicyEnrollmentIDUnresolvableMember(t *testing.T) {
	// member typed with an identity type that has no registered deserializer
	m0, err := identity.WrapWithType(identity.Type(99), []byte("cert-zero"))
	require.NoError(t, err)
	ai0, err := (&x509.AuditInfo{EID: "wallet-42"}).Bytes()
	require.NoError(t, err)
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0}, [][]byte{ai0})

	eid, _, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "", eid)
}

func TestPolicyEnrollmentIDMemberCountMismatch(t *testing.T) {
	m0, ai0 := newX509Member(t, "cert-zero", "wallet-42")
	m1, _ := newX509Member(t, "cert-one", "wallet-42")
	// two members but a single component audit info
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0, m1}, [][]byte{ai0})

	eid, _, err := newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "", eid)
}

func TestPolicyEnrollmentIDZeroValueDeserializer(t *testing.T) {
	// zero-value deserializer (no inner): legacy behavior, empty enrollment ID
	m0, ai0 := newX509Member(t, "cert-zero", "wallet-42")
	policyID, wrapped := newPolicyIdentity(t, [][]byte{m0}, [][]byte{ai0})

	d := deserializer.NewEIDRHDeserializer()
	d.AddDeserializer(Policy, &AuditInfoDeserializer{})

	eid, rh, err := d.GetEIDAndRH(t.Context(), policyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, "", eid)
	assert.Equal(t, "", rh)
}

func TestPolicyAuditInfoGarbageStillErrors(t *testing.T) {
	m0, _ := newX509Member(t, "cert-zero", "wallet-42")
	inner, err := (&PolicyIdentity{Policy: "$0", Identities: [][]byte{m0}}).Serialize()
	require.NoError(t, err)
	policyID, err := identity.WrapWithType(Policy, inner)
	require.NoError(t, err)

	_, _, err = newEIDRHDeserializer().GetEIDAndRH(t.Context(), policyID, []byte("not-json"))
	require.Error(t, err)
}
