# MSRV policy

**MSRV = 1.89**

1. MSRV is a promise to downstream users, not "the oldest version we happen to compile on".
2. MSRV bumps are allowed only in a minor release (during 0.x: `0.N` -> `0.N+1`). Never in a patch release.
3. MSRV must stay at or below `stable - 2`. Tightening to `stable - 1` requires an ADR.
4. Every crate declares `rust-version` (inherited from the workspace).
5. CI verifies MSRV in a dedicated job with a pinned toolchain.
6. A PR that violates this policy is rejected outright; there is no exception process.

## Why 1.89 and not higher

`aws-sigv4` would have forced MSRV 1.94.1. We deliberately do not depend on it for verification —
it has measured defects for server-side use (`?prefix=a+b` and `?prefix=a%20b` produce identical
signatures) — and port the two pure functions we need instead, which keeps MSRV at 1.89.
