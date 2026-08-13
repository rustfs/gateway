# RustFS Gateway

[![CI](https://github.com/rustfs/gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/rustfs/gateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.97.1-orange.svg)](docs/msrv.md)

**The HTTP layer of [RustFS](https://github.com/rustfs/rustfs).** It turns S3 traffic on the wire into typed operations
and back, and leaves storage semantics to RustFS itself.

This is where request routing, header and query typing, `aws-chunked` framing, XML codecs, SigV2/SigV4 and presigned-URL
verification, POST-policy handling, and the error shapes AWS actually returns all live.

**Scope, stated plainly:** this is built for RustFS. It is not a general-purpose library, we do not encourage outside
adoption, and nothing here is published to crates.io — RustFS consumes the repository as a git dependency. The API will
change whenever it suits RustFS.

### Why the crates are still layered

| Ring                | Crates                                                                                | Rule                              |
|---------------------|---------------------------------------------------------------------------------------|-----------------------------------|
| 0 — protocol kernel | `rustfs-gateway-types`, `-xml`, `-stream`, `-http`, `-sig`, `-model`, `-codegen`      | No dependency on any rustfs crate |
| 1 — service runtime | `rustfs-gateway-core`, `rustfs-gateway`, `-server`, `-conformance`                    | No dependency on any rustfs crate |
| 2 — RustFS edge     | `rustfs-gateway-admin`, `-console`, `-sts`, `-metadata-ext`, `-rpc` (not created yet) | May depend on rustfs crates       |

The rule survives the narrowed scope because it is not about reuse: `rustfs-gateway-types` is consumed by
`rustfs/ecstore`, `lifecycle`, `replication` and the scanner, and ring-2 crates depend on `ecstore`/`iam`/`policy` in
turn. **One ring-0 edge back into rustfs closes that cycle.** Membership is declared per crate in
`[package.metadata.gateway]` — after the rename the crate name says nothing — and `scripts/check_ring_boundaries.sh`
enforces it in CI.

`rustfs-gateway-server` is the generic transport boundary inside that repository scope: it can
host any compatible tower service and contains no RustFS business dependency. The facade and
deployment adapters remain RustFS-focused.

## Scope fence

The gateway is deliberately small at the edges. It **does not** and will not:

- **Implement storage.** No filesystem, no erasure coding, no bucket database. It hands the rest of RustFS a typed
  operation and expects a typed answer.
- **Evaluate IAM policy.** There is no policy language, no condition-key engine, no wildcard-ARN matcher. It defines an
  `Authorizer` interface and calls it; deciding "allow" or
  "deny" stays in `rustfs/iam`.
- **Own cluster or admin business logic.** Registering custom operations is a first-class mechanism — that is how the
  admin API, STS and console become ordinary operations that go through the same authentication and authorization
  pipeline — but their semantics live in ring 2, not in the protocol core.
- **Support non-HTTP access protocols.** SFTP and FTPS are out of scope, permanently.

Anything listed above being absent is a design decision, not a missing feature.

## Two guarantees the type system makes

**Signature verification cannot be skipped by accident.** `Signature` has no `PartialEq`; the only comparison is
`ct_verify`, and its only product is a `SignatureMatch` that nothing else can construct. `Verdict::Authenticated`
requires that value, so "the access key exists, therefore the request is authenticated" — MinIO's CVE-2025-31489 — does
not compile here.

**Secret-bearing values cannot be printed.** `SecretBytes` and `SigningKey` have no `Debug` at all, not a redacting one,
so the absence propagates to every type that contains them. Both zeroize on drop.

**A CORS preflight is answered without credentials, and never grants any.** It is the one endpoint an anonymous caller
reaches before the security floor, so its configuration read goes through a cache nothing can bypass, every refusal is
the same bytes whether or not the bucket exists, and a reflected `Origin` cannot be paired with
`Access-Control-Allow-Credentials` — that combination has no constructor, no reachable code path, and a guard script.

Details, including the ten-entry timing side-channel register, are in
[docs/security-model.md](docs/security-model.md); the preflight design is in [docs/cors.md](docs/cors.md).

Never run a debug build of `rustfs-gateway-sig` in production: `subtle` uses secret-dependent
`debug_assert!` checks. AWS compatibility also requires `InvalidAccessKeyId` and
`SignatureDoesNotMatch` to remain distinct; timing parity and rate limiting mitigate that
enumeration surface instead of changing the wire error code.

## Building

- **MSRV: 1.97.1.** Every crate declares `rust-version = "1.97.1"`; CI verifies it in a dedicated job. The policy —
  including when an MSRV bump is allowed — is in [docs/msrv.md](docs/msrv.md).
- **Development toolchain: 1.97.1**, pinned in `rust-toolchain.toml` together with the components (`rustfmt`, `clippy`,
  `rust-src`, `rust-analyzer`) that repository automation expects. `rustup` picks it up automatically inside a checkout.

```bash
cargo build --workspace          # build every crate
cargo xtask verify               # run the test suite
cargo xtask verify --crate rustfs-gateway-sig   # run one crate's tests
cargo fmt --all                  # format (settings in rustfmt.toml)
```

`cargo xtask` is the repository's automation entry point; prefer it over hand-rolled scripts so that local runs and CI
stay identical.

## Relationship to s3s

We thank the [s3s project](https://github.com/s3s-project/s3s): behavior reported in its issue and
pull-request history is an important source of facts for this project's acceptance cases. This
repository is not a fork and contains an independent implementation. Both projects use the
Apache-2.0 license; evidence here remains a link plus our own summary, never copied source code.

## Status

**Pre-alpha, and internal.** The API surface, crate boundaries and feature flags change without notice, and there is no
release channel to be compatible with: nothing is published, so the only consumer that matters is the RustFS commit that
pins this repository.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request — it covers the CLA, the
"no s3s code" rule, and the commit conventions. Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). To report a vulnerability, follow
[SECURITY.md](SECURITY.md); please do not open a public issue for security problems.

Working on this repository — whether you are a human or an AI agent — is governed by
[AGENTS.md](AGENTS.md): rule precedence, the verification gate, protected files, the dependency ring boundaries, and the
do-not-read list. Read it before your first change.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) — a single license, not a dual MIT/Apache offering, chosen so
that the patent grant applies uniformly to everyone who uses or contributes to this code. Attribution for third-party
material is recorded in
[NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be
licensed as above, without any additional terms or conditions.
