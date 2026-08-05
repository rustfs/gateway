# ADR-0004: SemVer policy for the public API and generated dto

- Status: Accepted
- Date: 2026-08-05
- Trigger: licensing/dependency policy (public API compatibility contract)
- Supersedes / Superseded by: none

## Context

RustFS Gateway is a library. Its public API is a hard contract with everyone who builds
on it, and the largest part of that API is generated: roughly 73 operations'
worth of Input and Output data-transfer objects, produced by codegen from the
AWS Smithy model. Once the generated shape is fixed it is extremely expensive to
change, because the change lands in every downstream construction site at once.

AWS adds fields to S3 shapes and values to S3 string enumerations continuously.
The policy question is therefore not "will the model change" but "which
generated shape makes model growth a minor version bump instead of a major one".

The intuitive answer — mark every dto `#[non_exhaustive]` so that adding a field
is never breaking — **is wrong in this specific situation**, and it is wrong in a
way that is easy to miss until it is far too late to reverse. This ADR freezes
the policy before the first line of codegen is written.

## Decision

Nine rules govern the generated shape and the versioning of this workspace.

| # | Rule |
|---|---|
| P1 | All Input and Output structs: **public fields plus `#[derive(Default)]`, and never `#[non_exhaustive]`**. Codegen must guarantee that every Output type can be constructed by `Default` |
| P2 | A new field in the AWS model must be generated as `Option<T>` (or a container with a `Default`), which makes it a **minor** bump. If codegen ever encounters a new **required, non-`Option`, non-`Default`** field, CI fails hard and a human must write an ADR |
| P3 | **Exhaustive destructuring of a dto is forbidden** (`let GetObjectInput { bucket, key } = x;`). It is the one usage that adding a field genuinely breaks. Non-exhaustive destructuring with `..` is the required spelling. RustFS has 56 existing sites to convert during migration; a guard script enforces the rule |
| P4 | **String enumerations** (`ChecksumAlgorithm`, `StorageClass`, `ReplicationStatus`, …) are generated as a **newtype over `Cow<'static, str>` with associated constants**, never as a real `enum`. AWS adds values every quarter; adding a constant is a pure minor bump |
| P5 | **Structural unions** (`AnalyticsFilter`, `SelectObjectContentEvent`, …) stay real `enum`s and **are** `#[non_exhaustive]`. Downstream matches on them but never constructs them, so the attribute is semantically right there |
| P6 | `S3ErrorCode` keeps its `Custom(String)` escape hatch and is `#[non_exhaustive]`. Adding an error code is a **minor** bump |
| P7 | Builders are the **recommended** construction path, not the only one. Codegen emits a builder for every Input, and that must never become a reason to remove the public fields |
| P8 | **The version carries the model snapshot**: `rustfs-gateway-types = "0.4.2+aws.2026-05-13"`. A model-date change gets its own CHANGELOG section. Field **removals and renames** from the model are batched and released only in a planned major version |
| P9 | `OperationSpec` is the **inverse case** and **should** be `#[non_exhaustive]` with a builder — it has very few construction sites, all of them inside this workspace |

Three additional rules cover the extension-point traits from ADR-0002:

- Adding a method to an extension-point trait **must** come with a default
  implementation; without one it is a major breaking change.
- Adding a supertrait is **always** major, which is why `Send + Sync + 'static`
  is fixed once and for all now.
- During `0.x`, each minor release may break. After `1.0`, strict SemVer applies.
  `rustfs-gateway-conformance` carries its own independent version number, because it is
  a product with a different release cadence from the framework.

## Evidence

Compiler results were measured with **rustc 1.97.1 (8bab26f4f 2026-07-14)** using
the `semver/` probe workspace. Note that the probe must be **cross-crate**:
`#[non_exhaustive]` has no effect within the defining crate, which is the single
easiest way to measure this wrongly.

**Measured 1: `#[non_exhaustive]` forbids functional update syntax, not merely
whole-struct literals.**

```rust
// upstream crate
#[non_exhaustive]
#[derive(Default)]
pub struct NexOut { pub a: Option<String>, pub b: Option<String> }

// downstream crate
NexOut { a: Some("x".into()), ..Default::default() }
```

```
error[E0639]: cannot create non-exhaustive struct using struct expression
```

**Measured 2 (control group, same experiment): a plain struct with `Default` is
already immune to added `Option` fields.**

```rust
// upstream crate — a new field c_new was added in this version
#[derive(Default)]
pub struct PlainOut { pub a: Option<String>, pub b: Option<String>, pub c_new: Option<String> }

// downstream crate — unchanged source, still compiles
PlainOut { a: Some("x".into()), ..Default::default() }
```

The combination of a plain struct, `#[derive(Default)]` and functional update
syntax already provides the property that `#[non_exhaustive]` was reached for.
s3s does exactly this today (`GetObjectOutput` carries only
`#[derive(Default)]`). **That is correct, and it must not be "improved".**

**Measured 3: counts from the RustFS main repository**, which is the migration
target and therefore the population this policy is optimising for.

| Metric | Value |
|---|---|
| `..Default::default()` occurrences, whole repository | **4,619** |
| …of those, occurrences in files that import `s3s::dto` | **2,100** (file-level upper bound) |
| …tightened to dto construction with a 12-line window regex | **254** (conservative lower bound) |
| Exhaustive destructuring of a dto | **56** |
| Real `enum` plus `non_exhaustive` in s3s today | **3** (all of them structural unions — consistent with P5) |
| `S3ErrorCode::Custom` uses in RustFS `tier.rs` | **28** (why P6 keeps the escape hatch) |

Adding `#[non_exhaustive]` to the dto would therefore break somewhere between
several hundred and two thousand construction sites in one step, **with no
mechanical fix available** — each site would have to be rewritten by hand into
builder form.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Mark dto structs `#[non_exhaustive]` | Measured `error[E0639]`: it forbids even `..Default::default()`. Breaks hundreds to thousands of construction sites with no mechanical fix, and buys a property the control group shows we already have |
| Builder-only dto with private fields | Same order of breakage, plus constructing the 46-field `PutObjectInput` through a builder is painful enough that users would wrap it again themselves |
| Generate string enumerations as real `enum` plus `non_exhaustive` | Forces `_ =>` arms all over downstream code, and AWS adds values every quarter, so every quarter would manufacture downstream noise. A newtype over `Cow` turns the same event into a pure minor bump |
| Newtype-wrap every dto field for future freedom | Every read becomes `.0`, polluting all 4,619 construction sites for a benefit nobody has asked for |
| Omit the model date from the version | A consumer could not tell which AWS model snapshot their build corresponds to. SemVer build metadata is designed for exactly this and does not participate in precedence comparison |
| Ship the ADR without guard scripts | Documentation blocks nothing. Both rules reduce to deterministic text checks, so they must be scripts |
| Adopt `cargo-semver-checks` now | There is no previous release to compare against; it would burn CI time to compare a version with nothing |

## Consequences

- **Codegen is constrained before it is written.** Every generated Input and
  Output is a plain struct with public fields and `Default`; every string
  enumeration is a `Cow` newtype with associated constants; only structural
  unions and `OperationSpec` carry `#[non_exhaustive]`. `P1` implements this.
- **Downstream constructs dto values with functional update syntax**, and adding
  an optional field upstream remains a minor bump. This is the whole point.
- **`..` is mandatory when destructuring.** The migration of RustFS's 56
  exhaustive destructuring sites to field access is part of `P9`.
- **Two deterministic guard scripts enforce this**, both running in the shared
  `arch-checks` CI job and both carrying rule references in their diagnostics:
  `scripts/check_no_dto_non_exhaustive.sh` (dto structs must not be
  `#[non_exhaustive]`; `OperationSpec` is the only allowlisted exception, and
  `enum`s are out of scope by construction) and
  `scripts/check_no_exhaustive_destructuring.sh` (no exhaustive destructuring of
  types named `*Input`, `*Output`, `*Request`, `*Response`). Both ship with
  tests in `scripts/test_semver_policy_checks.sh`. The destructuring check
  passes vacuously today because no dto exists yet — that is deliberate: **the
  rule must exist before the files do**, or the very first generated-dto pull
  request will contain the pattern it forbids.
- **Some checks are explicitly deferred**, and deferring them is part of this
  decision rather than an omission:

  | Deferred check | Until | Why |
  |---|---|---|
  | `cargo-semver-checks` | before the first release | No previous version exists to diff against; during `0.x` it stays a warning, never a blocker |
  | `cargo public-api` snapshot | before the first release | Same reason |
  | "dto public field count never decreases" ratchet | when dto codegen lands (`P1`) | It needs a baseline snapshot, which would be empty today. **The format is fixed now**: `docs/dto-field-counts.txt`, one `<TypeName> <count>` per line, sorted by name |
  | P2's hard CI failure on a new required non-`Option` field | when dto codegen lands (`P1`) | It needs codegen's semantic diff capability |

- **The version string grows a build-metadata suffix.** The CHANGELOG must preserve
  `+aws.<model-date>`, and must understand that it does not affect version precedence.
- **Nothing is published to crates.io** (decided after this ADR was accepted; see the
  Epic's scope amendment). rustfs consumes this repository as a git dependency, so the
  SemVer rules here bind the *source* contract with rustfs, not a registry release.
  `cargo-semver-checks` therefore compares against a git ref, not a published version.
