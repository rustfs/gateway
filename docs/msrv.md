# MSRV policy

**MSRV = 1.97.1**

1. MSRV is a promise to downstream users, not "the oldest version we happen to compile on".
2. MSRV bumps are allowed only in a minor release (during 0.x: `0.N` -> `0.N+1`). Never in a patch release.
3. MSRV must stay at or below `stable - 2`. Tightening to `stable - 1` requires an ADR.
4. Every crate declares `rust-version` (inherited from the workspace).
5. CI verifies MSRV in a dedicated job with a pinned toolchain.
6. A PR that violates this policy is rejected outright; there is no exception process.

## Why 1.97.1 and not higher

The workspace pins Rust 1.97.1 for development, so the crate-level `rust-version` now matches the
toolchain CI and local automation use. That keeps the compiler floor explicit for every consumer of
this git dependency while avoiding a moving `stable` channel.

`aws-sigv4` is still not used for verification: it has measured defects for server-side use
(`?prefix=a+b` and `?prefix=a%20b` produce identical signatures), and this repository only needs two
pure helper functions from it.
