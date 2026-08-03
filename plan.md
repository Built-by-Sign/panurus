# Plan — fix composite-owner (boolpolicy) audit accounting

## Goal

Policy (boolpolicy) wallets corrupt eid-keyed audit accounting: inbound
amounts multiply by the member count, and spent inputs are booked under the
counterparty's enrollment ID. Fix both at the SDK root so every consumer of
`Request.AuditRecord` sees correct data, without losing member-level identity
information (revocation handles, per-member visibility).

## Implementation Steps

1. [x] Done — derive the boolpolicy enrollment ID from its members
   (`NewAuditInfoDeserializer` composing the parent multiplex deserializer;
   htlc pattern).
2. [x] Done — count composite-owner outputs once per enrollment ID:
   keep every member row, collapse only for amount aggregation via
   `OutputStream.UniquePerOutput` applied in ttxdb
   `TransactionRecords`/`Movements` (shared by auditdb).
3. [x] Done — kill the first-output fallback in
   `completeInputsWithEmptyEID`: attribute each empty-EID input from its own
   token owner and the record-carried audit info
   (`WalletManager.GetEIDAndRH`), fail closed when unattributable.
4. [x] Done — surface malformed boolpolicy audit info as errors; only genuine
   cross-enrollment components report the legacy empty enrollment ID, and the
   whole component list is validated before declaring cross-enrollment.
5. [x] Done — docs: `docs/services/identity.md` boolpolicy enrollment-ID
   semantics.
6. [ ] Pending — split into upstream PRs: (a) boolpolicy EID derivation +
   error semantics, (b) UniquePerOutput economic aggregation, (c) auditor
   input attribution fail-closed.

## Notes & Decisions

- Cross-enrollment composite owners remain legal at the SDK layer ("" EID, one
  amount row per enrollment); single-wallet membership is a deployment-level
  constraint enforced by the application.
- An exported `AppendRecord`/record-injection API was considered and rejected:
  it conflicts with the audit-record cache isolation introduced by #1882.
- `Sum()` semantics unchanged; `UniquePerOutput` keys on (Index, EnrollmentID)
  so unfiltered streams never collapse across enrollments.
