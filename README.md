# s3gate

[![CI](https://github.com/rustfs/gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/rustfs/gateway/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-orange.svg)](docs/msrv.md)

**A protocol-exact, security-first S3 server framework for Rust** — it does everything
between the HTTP wire and S3 semantics correctly, and leaves storage semantics to you.

s3gate parses, validates, frames, and signs-checks S3 traffic: request routing, header and
query typing, `aws-chunked` framing, XML codecs, SigV2/SigV4 and presigned-URL verification,
POST-policy handling, and the error shapes AWS actually returns. What an object does once it
is understood — where bytes live, who is allowed to touch them — is your program's business.

This repository is also the home of the RustFS gateway: rings 0 and 1 are a reusable,
RustFS-independent S3 protocol framework, and ring 2 hosts the RustFS-specific HTTP surface
(admin API, console, STS, metadata extensions, RPC prefix routing) that will take over the
entire HTTP layer of [RustFS](https://github.com/rustfs/rustfs).

| Ring | Crates | Rule |
|---|---|---|
| 0 — protocol kernel | `s3gate-types`, `s3gate-xml`, `s3gate-stream`, `s3gate-http`, `s3gate-sig`, `s3gate-model`, `s3gate-codegen` | Reusable, zero RustFS dependencies |
| 1 — service runtime | `s3gate-core`, `s3gate`, `s3gate-conformance` | Reusable, zero RustFS dependencies |
| 2 — RustFS edge | `rustfs-gateway-admin`, `-console`, `-sts`, `-metadata-ext`, `-rpc` (not created yet) | May depend on published RustFS crates |

Rings 0 and 1 must never depend on a RustFS crate or on a ring-2 crate. That constraint is
what keeps the cross-repository dependency graph acyclic, and it is enforced in CI.

## Scope fence

s3gate is deliberately small at the edges. It **does not** and will not:

- **Implement storage.** No filesystem, no erasure coding, no bucket database. s3gate hands
  you a typed operation and expects a typed answer.
- **Evaluate IAM policy.** There is no policy language, no condition-key engine, no
  wildcard-ARN matcher. s3gate defines an `Authorizer` interface and calls it; deciding
  "allow" or "deny" is entirely yours.
- **Own cluster or admin business logic.** s3gate does provide a first-class mechanism for
  registering custom operations, so admin-style APIs can be layered on top — but their
  semantics are not part of this framework.
- **Support non-HTTP access protocols.** SFTP and FTPS are out of scope, permanently.

Anything listed above being absent is a design decision, not a missing feature.

## Relationship to s3s

[s3s](https://github.com/Nugine/s3s) is the S3 protocol crate that RustFS used before this
project existed. Three things about the relationship, stated up front:

1. **Acknowledgement.** The issue and pull-request history of s3s is a valuable public record
   of how real S3 clients and the real AWS service behave. Those *facts about the protocol*
   are an important source for s3gate's conformance corpus, and we are grateful for the work
   that produced them. Each conformance case cites its evidence as a URL plus an original
   one-line summary; discussion text itself is never pasted into this repository.
2. **s3gate is not a fork of s3s.** It is an independent implementation, written from
   scratch. It contains no source code copied from s3s, and contributors are explicitly
   forbidden from introducing any — see [CONTRIBUTING.md](CONTRIBUTING.md).
3. **Both projects are licensed under Apache-2.0.** s3s is Apache-2.0; so is s3gate. There is
   no license incompatibility between them, and no license-derived obligation is being evaded
   by the choice above.

## Building

- **MSRV: 1.89.** Every crate declares `rust-version = "1.89"`; CI verifies it in a dedicated
  job. The policy — including when an MSRV bump is allowed — is in [docs/msrv.md](docs/msrv.md).
- **Development toolchain: 1.97.1**, pinned in `rust-toolchain.toml` together with the
  components (`rustfmt`, `clippy`, `rust-src`, `rust-analyzer`) that repository automation
  expects. `rustup` picks it up automatically inside a checkout.

```bash
cargo build --workspace          # build every crate
cargo xtask verify               # run the test suite
cargo xtask verify --crate s3gate-sig   # run one crate's tests
cargo fmt --all                  # format (settings in rustfmt.toml)
```

`cargo xtask` is the repository's automation entry point; prefer it over hand-rolled scripts
so that local runs and CI stay identical.

## Status

**Pre-alpha.** Nothing here is stable yet: the API surface, crate boundaries, and feature
flags all change without notice. During `0.x`, **every minor release may contain breaking
changes** (`0.N` → `0.N+1`), and an MSRV bump is also only ever allowed in a minor release.
Do not build production systems on it yet.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request — it covers the CLA, the
"no s3s code" rule, and the commit conventions. Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). To report a vulnerability, follow
[SECURITY.md](SECURITY.md); please do not open a public issue for security problems.

Working on this repository — whether you are a human or an AI agent — is governed by
[AGENTS.md](AGENTS.md): rule precedence, the verification gate, protected files, the dependency
ring boundaries, and the do-not-read list. Read it before your first change.

## License

Licensed under the [Apache License, Version 2.0](LICENSE) — a single license, not a dual
MIT/Apache offering, chosen so that the patent grant applies uniformly to everyone who uses
or contributes to this code. Attribution for third-party material is recorded in
[NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this project shall be licensed as above, without any additional terms or conditions.
