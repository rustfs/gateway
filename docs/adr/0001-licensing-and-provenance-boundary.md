# ADR-0001: Licensing and provenance boundary

- Status: Accepted
- Date: 2026-08-05
- Trigger: licensing/dependency policy
- Supersedes / Superseded by: none

## Context

RustFS Gateway is an independent implementation of the server side of the S3 protocol.
It is not a fork of [`s3s`](https://github.com/s3s-project/s3s), but it is being
written by people who have read s3s closely, who have mined its issue tracker
for behavioural facts, and who intend the result to be adopted by the RustFS
main repository. That combination makes provenance a first-class engineering
concern rather than a paperwork exercise.

Two questions had to be answered before the first line of generated or
hand-written code landed:

1. **Which licence does RustFS Gateway ship under** — Apache-2.0 only, or the Rust
   ecosystem's customary `MIT OR Apache-2.0` dual licence?
2. **What exactly may be taken from the projects we learn from** — s3s source,
   s3s issues and pull requests, the AWS Smithy model, external conformance
   suites, and MinIO?

`P0-01` already landed the single-licence answer in `LICENSE`, `NOTICE` and
`README.md`. This ADR records *why*, so that the next "Rust convention is dual
licensing" pull request can be answered with a document instead of a debate.

## Decision

**RustFS Gateway is licensed under Apache-2.0 only.** No `LICENSE-MIT`, no dual-licence
header, no per-file `SPDX-License-Identifier` claiming otherwise.

**Provenance is governed by three categories**, and every contributor —human or
agent— must classify what they are about to reuse before reusing it:

| Category | Copyright status | Allowed | Forbidden |
|---|---|---|---|
| 1. **Code** from s3s (including its tests, CI workflows and reporting scripts) | Covered by Apache-2.0 | In principle copyable, provided the copyright notice is retained, the file header records the source and commit, and `NOTICE` credits it | **Forbidden outright in this project.** Rewriting costs less than carrying a permanent provenance trail. We copy knowledge, not code |
| 2. **Behavioural facts** stated in s3s (or any other project's) issues and pull requests | Facts are not copyrightable; the prose of an issue body remains its author's copyright | Free use of the fact; conformance cases are re-authored from the fact | Pasting issue or PR prose into this repository. Evidence entries store a **URL plus our own summary**, never the original text |
| 3. **Methodology** for consuming the AWS Smithy model | A methodology is not copyrightable | Free to borrow — how to walk shapes, how to map http bindings, how to lay out generated modules | Copying another project's codegen source without attribution (which category 1 forbids anyway) |

**Adjacent rules that follow from the same reasoning:**

- **MinIO is clean-room only.** `minio/minio` is AGPL-3.0 and the repository is
  archived. Any RustFS Gateway work that targets MinIO behavioural compatibility must be
  derived from observable behaviour, captured traffic, or public documentation —
  never from reading MinIO source. Contributors who have read MinIO source
  recently should not be the ones writing the corresponding compatibility code.
- **External test suites are invoked, not vendored.** Ceph `s3-tests` (MIT) and
  `mint` (Apache-2.0) are run as external runners at a pinned revision recorded
  in this repository. Their sources are not copied into the tree, so their
  licences never mix into our distribution and their upgrades stay a
  one-line revision bump.
- **Codegen strips the AWS `documentation` trait by default.** Generated rustdoc
  carries (a) one sentence we wrote, (b) a URL to the official AWS documentation
  page, and (c) the relevant quirk id — never the AWS prose itself.
- Where a small, well-identified pure function is ported from an Apache-2.0
  source (for example `generate_signing_key` and `calculate_signature` from
  `aws-sigv4`), attribution is mandatory at the file level and in `NOTICE`.
  This is the *only* sanctioned form of code reuse, and it is an exception that
  requires the porting PR to say so explicitly.

## Evidence

**Measured licence facts (verified 2026-08-05 by reading the repositories):**

| Project | Licence | How it was verified |
|---|---|---|
| **s3s** | **Apache-2.0** | Repository `LICENSE` is the full Apache License 2.0 text; root `Cargo.toml` declares `license = "Apache-2.0"`, and all 9 member crates use `license.workspace = true` |
| RustFS main repository | Apache-2.0 | `LICENSE` |
| rustfs/cli | MIT **OR** Apache-2.0 | `LICENSE-MIT` plus `LICENSE-APACHE` |
| AWS Smithy S3 model | Apache-2.0, from `aws/api-models-aws`, path `models/s3/service/2006-03-01/s3-2006-03-01.json`; the repository publishes **no tags**, so it can only be pinned by commit SHA | Repository `LICENSE` and Epic "technology baseline" |
| Ceph `s3-tests` | MIT | Repository `LICENSE` |
| `mint` | Apache-2.0 | Repository `LICENSE` |
| `minio/minio` | **AGPL-3.0**, repository **archived** | Repository `LICENSE` and GitHub archive banner |

**Measured: s3s carries no per-file copyright headers.** `grep Copyright` over
the s3s source tree returns no hits, and the repository has no `NOTICE`, no
`SECURITY.md` and no `CODE_OF_CONDUCT.md`. Consequence: if s3s code were ever
copied, there would be no per-file notice to preserve — attribution could only
be made at the whole-project level, which is a weaker and more error-prone form
of compliance. This measurement is one of the reasons category 1 is forbidden
outright rather than merely regulated.

**Measured: the AWS Smithy S3 model contains 1,628 occurrences of
`smithy.api#documentation`.** The values are AWS service documentation prose —
HTML fragments containing `<p>`, `<i>Amazon S3 User Guide</i>` and links back to
`docs.aws.amazon.com`. This is materially different from the model's structural
data (shapes, traits, http bindings), which is a description of an interface
that we are entitled to implement.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| **`MIT OR Apache-2.0` dual licence** (the Rust ecosystem convention; rustfs/cli uses it) | Dual licensing hands downstream users a pure-MIT option, and a derivative of Apache-2.0 code cannot be offered under pure MIT. Keeping that promise honest would require proving, continuously and forever, that RustFS Gateway is a clean-room implementation containing zero s3s code. That standing burden of proof outweighs the convenience the MIT option buys downstream |
| **MIT only** | Loses the explicit patent grant, which is the single most valuable clause for a project that implements a published protocol and may brush against patents |
| **Copy s3s code with attribution** (permitted by Apache-2.0 §4) | Legal, but every copied file becomes a permanent provenance obligation: header, `NOTICE` entry, and a merge decision every time upstream changes. Rewriting from behavioural knowledge is cheaper on a horizon longer than a few months, and it is what "independent implementation" in the README must mean to stay true |
| **Vendor Ceph `s3-tests` and `mint` into the tree** | Mixes MIT and Apache-2.0 sources into our distribution for no benefit; pinning an external revision gives the same reproducibility with none of the licence surface |
| **Read MinIO source for behaviour compatibility** | AGPL-3.0. Reading it contaminates the reader for clean-room purposes, and the repository is archived so there is no upstream to coordinate with. Behaviour must come from observation and documentation |
| **Keep the AWS `documentation` trait in generated code** | Three separate costs: the murkiest licence status of anything in the model, a much larger generated artifact, and thousands of lines of HTML prose that drown `grep` for every agent working in `generated/` |
| **Leave the licence choice undocumented because `LICENSE` already exists** | A file states the outcome, not the reasoning. Without this ADR the decision gets relitigated by anyone who notices the ecosystem convention |

## Consequences

- **Downstream users get one licence and one patent grant.** There is no MIT
  escape hatch, and that is intentional; it is also what makes adoption by the
  Apache-2.0 RustFS main repository frictionless.
- **`LICENSE`, `NOTICE`, `README.md` and this ADR must agree.** If any future
  change makes them disagree, the ADR is the record of intent and the other
  files are the bug.
- **Contributors must classify before reusing.** The three-category table is
  mirrored in `CONTRIBUTING.md`; the practical rule is "copy knowledge, never
  copy code", with the single narrow exception of attributed pure-function ports.
- **Evidence entries carry URLs plus our own summaries.** This is why the quirks
  table format stores `evidence = ["s3s-issue:632", ...]` rather than quoted
  issue text, and it is why the conformance corpus is re-authored rather than
  imported.
- **Codegen owes rustdoc a replacement.** Stripping the AWS documentation trait
  means the generator must emit our own one-line summary plus the upstream URL
  for every operation and shape; "no documentation at all" is not an acceptable
  outcome of this decision, and `P1` owns that work.
- **The pinned Smithy model commit SHA is a licensing artifact, not just a
  reproducibility one.** Whatever pins the model must record the SHA in a
  protected file so the provenance of the generated code is auditable.
- **This ADR requires human review.** Licensing conclusions must not be accepted
  on the strength of an agent verdict alone.
