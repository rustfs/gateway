# Architecture Decision Records

This directory is the durable record of the decisions that shape this project. It is
deliberately tiny: a numbering rule, a status vocabulary, an immutability rule,
a template, and a hand-maintained index. There is no review board, no state
machine, and no generator.

## When you MUST write an ADR

Exactly three triggers. Nothing else qualifies.

1. Overturning one of the project's five axioms (A1 protocol exceptions are data,
   not code branches; A2 unsafe spellings must fail to compile; A3 ordering
   contracts are fixed by types; A4 extension points are symmetric in
   granularity; A5 generated code is minimal and diffable).
2. Changing a crate boundary — adding, removing or merging a crate, or changing
   a dependency direction between crates.
3. Changing the licensing or dependency policy.

If your change is not one of these three, do NOT write an ADR. Design notes,
investigation write-ups and progress reports do not belong in this repository at
all; the issue is the single source of truth for those.

## Rules

- **File name**: `NNNN-kebab-case-title.md`, four decimal digits, monotonically
  increasing from `0001`, never reused. `README.md` and `0000-template.md` are
  the only other files allowed in this directory.
- **Status** is exactly one of `Accepted`, `Superseded by ADR-NNNN`, or
  `Rejected`. There is no `Proposed` state: an ADR is reviewed inside its own
  pull request and becomes `Accepted` the moment that PR merges.
- **Merged ADRs are immutable** apart from typo fixes. To overturn a decision,
  write a new ADR and mark the old one `Superseded by ADR-NNNN`. Never edit the
  old decision in place — squash-merge destroys the history that `git blame`
  would otherwise recover. This is enforced by the Protected Files gate in
  `AGENTS.md`: touching an existing ADR requires a PR labelled `BREAKING`.
- **Every ADR MUST carry an `## Evidence` section** with reproducible facts:
  compiler error codes and the exact `rustc` version, measured counts and the
  command that produced them, benchmark numbers. Every claim in that section
  must say whether it is *measured* or `[inferred]`. "It seemed cleaner" is not
  evidence, and an ADR whose Evidence section contains only prose is not
  reviewable.
- **Every ADR MUST carry a `## Rejected alternatives` section** that names each
  option considered and the concrete reason it lost. An ADR that only argues for
  the winner has not made a decision, it has written an advertisement.

## Structure

Every ADR has a metadata block followed by exactly five level-2 sections, in
this order: `Context`, `Decision`, `Evidence`, `Rejected alternatives`,
`Consequences`. Copy [`0000-template.md`](0000-template.md) into `docs/adr/NNNN-your-title.md`.
The template lives in exactly one place; it is deliberately not reproduced here, because a
second copy is a second thing to keep in sync.

## Index

| ADR | Title | Status |
|---|---|---|
| 0001 | Licensing and provenance boundary | Accepted |
| 0002 | dyn and async policy for extension points | Accepted |
| 0003 | No global-registry crates (inventory / linkme / ctor) | Accepted |
| 0004 | SemVer policy for the public API and generated dto | Accepted |
| 0005 | The generated dto crosses the package boundary by symlink | Accepted |
| 0006 | Static operation dispatch across the core-facade boundary | Accepted |
| 0007 | Runtime vtables for dialect XML fields | Superseded by ADR-0010 |
| 0008 | Closed error resolution across the types, signature, core and facade boundary | Accepted |
| 0009 | Typed scope-region rejection across sig and gateway | Accepted |
| 0010 | Box the public DTO inside handler requests | Accepted |
| 0011 | Handler deadlines propagate explicit cancellation | Accepted |
| 0012 | Verified request bodies cross the handler boundary as streams | Accepted |
| 0013 | Freeze committed response heads before detached work | Accepted |
| 0014 | Self-held HTTP/1.1 response transport | Accepted |
| 0015 | Required streaming request members use controlled construction | Accepted |
| 0016 | Explicit construction for required structural-union inputs | Accepted |
| 0017 | Carry the SSE enforcement proof on handler requests | Accepted |
| 0018 | The dialect vtable decision of ADR-0007 stands; ADR-0010 replaced only its request layout | Accepted |
| 0019 | Bounded JSON validation for the KMS encryption context | Accepted |
| 0020 | Carry the verified credential scope on the authentication verdict | Accepted |
| 0021 | Delegate anonymous admission to the Authorizer at service level | Accepted |
| 0022 | A typed, read-only request context on handler requests | Accepted |
| 0023 | An opt-in any-region signing scope for RustFS clients | Accepted |
| 0024 | Dialect path-prefix claims, path templates, alias rows, a per-operation caller secret and service-level operations | Accepted |
| 0025 | Action rules, subject rules and bound buckets for RustFS's custom-auth admin routes | Accepted |
| 0026 | Account sets, query-bound buckets, and anonymous admin bootstrap | Accepted |
| 0027 | Service-level template parameters, literal-over-parameter shadowing, and the caller secret for RustFS's order-3 admin routes | Accepted |
| 0028 | Subject rules for RustFS's order-4 admin routes: own-account labels, refused absences, and alias spellings | Accepted |
| 0029 | RustFS's alias spellings of a subject parameter name the same account | Accepted |
| 0030 | Bound buckets, query buckets and the trailing-slash heal route for RustFS's order-5 admin routes | Accepted |
| 0031 | The table catalog's two surfaces as claims and alias rows, `{warehouse}` bound, and first-divergence shadowing | Accepted |
| 0032 | The last admin orders: the anonymous OIDC bootstrap generated, the profiling claims, and the routes that stay with RustFS | Accepted |
| 0033 | MinIO's bucket-configuration members are part of every assembly's HTTP codec | Accepted |
| 0034 | An embedding host may lift the framework's handler, continuation and body deadlines | Accepted |
| 0035 | Admit presigned URLs on every standard operation at service level | Accepted |
| 0036 | A trailing catch-all template parameter | Accepted |

The index is hand-maintained. Generating it would cost more than it saves until
there are at least fifteen records.
