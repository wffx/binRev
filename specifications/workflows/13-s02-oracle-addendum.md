# S02 Forward-Test Oracle 附录

This addendum is part of the S02 workflow contract and applies only to lab validation runs where a paired symbolized IDB is explicitly provided by the user.

## Scope

- A symbolized oracle such as `tests/xen-syms_arm64.i64` is a validation-only artifact.
- It may be used to tune S02 function-boundary and `.inst fallback` recovery in the test case.
- It is not a production input and must not appear as evidence in recovered production `functions.jsonl`, `data-objects.jsonl`, `call-graph.json`, or final source-map claims.

## Ordered workflow

1. Build an oracle relation from byte/function fingerprints, dominant address delta, size, and branch-local CFG shape.
2. Use target-only IDA evidence to make the primary S02 proposal.
3. Compare the target proposal against the oracle and write the report under `validation/oracle/`.
4. If the user explicitly authorizes oracle-assisted lab repair, convert only target words that map to oracle code and record the action as `validation_only`.
5. Re-export target word state after every apply pass.
6. Repeat apply/readback until oracle-code candidates reach zero, or record the remaining candidates as S02 residual blockers.

## Exit rule

S02 remains `rework_required` if any non-waived target middle `.text` word is still:

- mapped to oracle code but not represented as target code,
- represented only by stale `.inst fallback` comments,
- hidden by IDA item-head/tail ambiguity,
- or blocked by function-boundary/segment-coverage mismatch.

Only after those residuals are fixed, waived with explicit reviewed rationale, or proven to be outside target `.text` may S02 proceed to S03.

When residuals are waived, S02 may be marked `accepted` only if:

- each waived address is represented in `accepted-risk-*.jsonl`,
- `stage-manifest.json` records `residual_policy.status = accepted-risk`,
- downstream stages include the accepted-risk artifact in their input provenance,
- and any downstream conclusion directly depending on a waived address is downgraded to `inferred` or `unresolved`.
