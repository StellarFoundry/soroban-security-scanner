# Rule Calibration Report

- **Schema version:** 1
- **Tool:** soroban-scan
- **Corpus:** `fixtures/corpus`
- **Scope:** `built-in-defaults`
- **Rules covered:** 47
- **Rules flagged for review:** 43
- **Rules with incomplete corpus coverage:** 0

This report is advisory. It does not change severity or confidence. Severity is impact-based and is never derived from fixture counts. Confidence candidates require maintainer review with corpus evidence. Ambiguous fixtures are recorded and excluded, never guessed.

| Rule | Title | Severity | Confidence | TP | FP | FN | TN | Ambiguous | Corpus | Review |
| ---- | ----- | -------- | ---------- | -- | -- | -- | -- | --------- | ------ | ------ |
| SS-001 | State-changing entry point without caller authorization | high | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-002 | Cross-contract call without caller authorization | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-003 | Unbounded storage iteration in an entry point | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-004 | Panic-prone construct in a contract entry point | low | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-005 | Unsafe code in a Soroban contract | medium | high | 1 | 0 | 0 | 3 | 0 | complete | no |
| SS-006 | Persistent storage write without TTL management | low | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-007 | Hardcoded Stellar account or contract address | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-008 | Unchecked arithmetic in a contract entry point | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-009 | Insecure randomness derived from ledger state | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-010 | Privileged state change without an event | low | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-011 | Initialization entry point without a re-initialization guard | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-012 | Unbounded collection growth in an entry point | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-013 | Cross-contract call before state update | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-014 | Token transfer amount without validation | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-015 | Deprecated Soroban SDK version | low | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-016 | Unbounded data stored in instance storage | medium | low | 3 | 0 | 0 | 3 | 0 | complete | yes |
| SS-017 | Authorization after state mutation | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-018 | Unchecked integer cast | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-019 | Ignored cross-contract call result | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-020 | Unvalidated XDR or bytes deserialization | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-021 | Durable data written to temporary storage | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-022 | Unsafe symbol_short key | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-023 | Sensitive-looking data published in events | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-024 | Missing contracttype on boundary types | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-025 | Unbounded string/bytes persisted from caller input | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-026 | TTL constant outside the expected range | low | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-027 | Contract's own address used as an authorization subject | high | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-028 | Cross-contract call without a reentrancy guard | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-029 | Public test or debug hook in a contract entry point | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-030 | Token client built from an unvalidated caller address | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-031 | Event topic derived from a caller-controlled parameter | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-032 | Redundant require_auth in loop | low | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-033 | Wildcard import from the Soroban SDK | low | high | 1 | 0 | 0 | 3 | 0 | complete | no |
| SS-034 | Unvalidated deployer usage | high | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-035 | Ignored checked-arithmetic result | high | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-036 | Deprecated SDK API usage | low | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-037 | Competing authorization calls | medium | low | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-039 | Persistent storage read without TTL management | medium | low | 1 | 0 | 0 | 4 | 0 | complete | yes |
| SS-041 | Authorization check inside a loop | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-042 | Security check unreachable on every path | low | medium | 2 | 0 | 0 | 4 | 0 | complete | yes |
| SS-043 | Hardcoded Stellar network passphrase | medium | high | 1 | 0 | 0 | 3 | 0 | complete | no |
| SS-044 | Cross-contract call with an unvalidated address argument | medium | low | 1 | 0 | 0 | 4 | 0 | complete | yes |
| SS-045 | Cross-contract call without error handling | medium | medium | 1 | 0 | 0 | 3 | 0 | complete | yes |
| SS-046 | Duplicate storage key construction | medium | low | 1 | 0 | 0 | 5 | 0 | complete | yes |
| SS-047 | Unchecked ledger timestamp usage | medium | low | 1 | 0 | 0 | 5 | 0 | complete | yes |
| SS-048 | Unbounded event payload | medium | medium | 1 | 0 | 0 | 5 | 0 | complete | yes |
| SS-049 | Unchecked bytes-to-string conversion | medium | high | 1 | 0 | 0 | 5 | 0 | complete | no |

## Review candidates

### SS-001 — State-changing entry point without caller authorization

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-002 — Cross-contract call without caller authorization

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-003 — Unbounded storage iteration in an entry point

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-004 — Panic-prone construct in a contract entry point

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-006 — Persistent storage write without TTL management

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-007 — Hardcoded Stellar account or contract address

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-008 — Unchecked arithmetic in a contract entry point

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-009 — Insecure randomness derived from ledger state

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-010 — Privileged state change without an event

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-011 — Initialization entry point without a re-initialization guard

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-012 — Unbounded collection growth in an entry point

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-013 — Cross-contract call before state update

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-014 — Token transfer amount without validation

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-015 — Deprecated Soroban SDK version

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-016 — Unbounded data stored in instance storage

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-017 — Authorization after state mutation

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-018 — Unchecked integer cast

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-019 — Ignored cross-contract call result

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-020 — Unvalidated XDR or bytes deserialization

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-021 — Durable data written to temporary storage

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-022 — Unsafe symbol_short key

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-023 — Sensitive-looking data published in events

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-024 — Missing contracttype on boundary types

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-025 — Unbounded string/bytes persisted from caller input

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-026 — TTL constant outside the expected range

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-027 — Contract's own address used as an authorization subject

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-028 — Cross-contract call without a reentrancy guard

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-029 — Public test or debug hook in a contract entry point

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-030 — Token client built from an unvalidated caller address

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-031 — Event topic derived from a caller-controlled parameter

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-032 — Redundant require_auth in loop

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-034 — Unvalidated deployer usage

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-035 — Ignored checked-arithmetic result

- **severity:** no_change (high)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-036 — Deprecated SDK API usage

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-037 — Competing authorization calls

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-039 — Persistent storage read without TTL management

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-041 — Authorization check inside a loop

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-042 — Security check unreachable on every path

- **severity:** no_change (low)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-044 — Cross-contract call with an unvalidated address argument

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-045 — Cross-contract call without error handling

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-046 — Duplicate storage key construction

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-047 — Unchecked ledger timestamp usage

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (low); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

### SS-048 — Unbounded event payload

- **severity:** no_change (medium)
  - severity measures impact; corpus counts measure detection evidence only
  - any severity change requires a human impact justification in the PR
- **confidence:** review_candidate (medium); candidate `high`
  - curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change

