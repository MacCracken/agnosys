# cyrius `#deprecated("reason")` attribute — unproven across agnosticos

**Status:** OPEN (passive — defer until proven elsewhere; not a bug, just untested in production by any first-party consumer).
**Filed:** 2026-05-09
**Reporter:** agnosys 1.2.0 (during V1.2.4 slot scoping — `#deprecated` adoption channel for graceful API drift before removal).
**cyrius version observed:** 5.10.19.
**Severity:** LOW — workaround (plain comments + CHANGELOG `Breaking` sections) is adequate. Don't refile or pre-validate.

## Summary

Cyrius reportedly supports a `#deprecated("reason / migration")` attribute for marking public fns as deprecated with a graceful path before removal. agnosys would adopt it for V1.2.4 to handle any post-1.0 API drift cleanly.

**However:** grepping across the agnosticos consumer ecosystem (yukti / sigil / patra / kavach src/ trees) returns **0 sites** using `#deprecated`. The directive may be implemented in cyrius but no first-party consumer has shipped it in production. Adopting it from agnosys's side would be the first real-world test.

Per the agnosys agent's "low-risk slot selection" memory rule, slots that depend on cyrius features without an in-tree consumer precedent are deferred — they tend to surface upstream bugs that would be agnosys's first-from-scratch reproducer (the V1.1.15 `#ifplat` slot was the cautionary tale: cyrius's own stdlib documented the regression but agnosys reproduced it from scratch anyway).

## Why this matters for agnosys

V1.2.4 wants graceful deprecation as a future-proofing slot. Today agnosys hasn't actually had to deprecate anything — V1.0.x → V1.1.x → V1.2.x has been purely additive (no removed fns, no signature changes, per the API-surface gate). The directive becomes useful when the first real removal lands; preemptive adoption isn't worth the bug-finding risk.

## Workaround

Plain comments + CHANGELOG `Breaking` sections handle the deprecation use case adequately:

```cyr
# DEPRECATED (V1.X.Y): use foo_v2() instead. This wrapper stays
# for the V1 API contract; will be removed in V2.0.
fn foo(...) { return foo_v2(...); }
```

Plus a `### Breaking` block in the relevant CHANGELOG entry.

## Mitigation when proven

When *any* of the agnosticos consumers (yukti / sigil / patra / kavach / etc.) adopts `#deprecated` first, agnosys can follow the same pattern. The signal: a `#deprecated(...)` attribute appearing in their src/ tree, building clean across releases.

## Why this isn't filed upstream as a fresh issue

It's not a bug. The directive may work fine — agnosys just hasn't tested it. Pre-validating from the consumer side risks discovering and reporting any latent issues, which is exactly the busywork pattern the agent's memory rules guard against.

When agnosys actually needs to deprecate something, this issue reopens — at that point the cost-benefit of trying `#deprecated` vs the comment-and-CHANGELOG workaround is concrete.

## Status

- agnosys cyrius pin: 5.10.19.
- agnosys V1.2.4: deferred indefinitely. Reopens when (a) another agnosticos consumer adopts the directive in production, OR (b) agnosys actually has a fn to deprecate.
