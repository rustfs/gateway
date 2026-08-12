# AGENTS.md

This repository is developed primarily by AI agents. This is the single rule file: read it end to
end before your first edit, and you know the rule order, what to run before committing, which files
need a Breaking Change process, what is forbidden outright, which way dependencies may point, what
to tick on a PR — and **which files you must never open**.

Governance context lives in `README.md` (scope fence, relationship to s3s), `CONTRIBUTING.md`
(contribution process), and `SECURITY.md` (disclosure). This file never contradicts them.

## Rule Precedence

Highest wins on conflict:

1. **Absolute Prohibitions** in this file. No exceptions, no "just this once", no task-specific waiver.
2. Explicit instructions from the user or from the task issue.
3. The remaining sections of this file.
4. A crate-scoped `AGENTS.md` (none exists today).
5. Source comments and rustdoc.
6. General Rust convention.

**Layering trigger — do not create a scoped AGENTS.md before it fires.** A crate may get its own
scoped AGENTS.md only when it has **5 or more rules that apply to that crate alone**. The known failure
mode of layered rule files is that an agent reads the nearest scoped file and never reads the root
one; with total rules under 400 lines, layering only dilutes and duplicates. The PR that introduces
the first scoped file must land `scripts/check_agents_no_dup.sh` (sentence-level duplicate
detection between root and scoped files) in the same PR.

## Language Requirements

Everything that lands is **English**: source code, identifiers, comments, rustdoc, error and log
messages, commit messages, PR titles and descriptions, Markdown docs, conformance case names,
script output — and **issues, issue comments, PR reviews, and release notes in this repository**.

Across the `rustfs` organisation, `rustfs/backlog` is the single exception: planning and design
discussion there may be Chinese. Every other repository, this one included, is English-only for
anything that lands, and that covers the GitHub surface, not just the source tree. Anything
written once is read by everyone who touches it afterwards — including contributors who do not
read Chinese, and the greps that go looking for it.

Chinese is fine in exactly one place: conversation with an AI assistant. Translate before it
lands. "It is only an issue comment" is not an exception, and neither is "it is only a comment".

## Workflow

### Branch and baseline

- Always branch from the **latest `origin/main`**. `git fetch origin` first, every time.
- Branch name: `<phase>/<issue-id>-<slug>`, e.g. `p2/142-sigv4-streaming`. The issue id in the
  branch name is what lets any device do `git fetch && git switch p2/142-sigv4-streaming` and
  continue the same task.
- One task, one worktree. **Never commit in a shared checkout.**
- Prefer **stacked PRs** over waiting: if task B depends on unmerged task A, branch B from A and
  set A as the PR base. Serial waiting is the main throughput killer with parallel agents.

### The four-command gate

Run in this order; all four must pass before you create a commit.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask verify --crate <the crate you changed>
```

Exemption: a change that touches **only** Markdown files unrelated to executable behaviour may skip
the gate. This does not extend to schemas, generated output, CI config, or scripts.

### Feedback-loop latency

Feedback latency is the first-order metric of an AI-friendly codebase, ahead of naming and directory
shape. The rule: after changing a crate you must **know exactly one command to run**, and that
command must go red or green in **≤30 seconds**. `cargo xtask verify --crate <name>` is that
command. If it exceeds 30 seconds for any crate, that is a bug — open an issue, do not absorb it.

Use this map rather than guessing a broader command:

| What changed | Run |
| --- | --- |
| One operation, its codec, or its route | `cargo xtask verify --op <OperationName>` |
| One crate | `cargo xtask verify --crate <crate-name>` |
| The pinned model, an overlay, or code generation | `cargo xtask codegen --check` |
| One conformance case | `cargo xtask conformance validate --filter '<case-id>'` |
| Cross-crate wiring, scripts, or CI | `cargo xtask verify --all` |

`verify --op` and `verify --crate` have a 30-second budget. `verify --all` is the CI surface and has
a 10-minute budget. A budget failure is a tooling defect; do not replace the command with a wider,
slower one.

### TDD

Write the failing test first, watch it fail, then implement. Implementing first and back-filling
tests afterwards is forbidden: a test written against code you just wrote asserts what the code
does, not what the protocol requires. Negative cases (rejections, malformed input, boundary
violations) must outnumber positive ones.

### Multi-device and multi-agent collaboration

- **The GitHub issue is the single source of truth.** Progress, decisions, dead ends, and surprises
  go into issue comments — never into a file in this repository.
- Before handing off or ending a session, append a **Handoff comment** to the issue in exactly this
  shape:

  ```markdown
  ### Handoff
  - Done: <what is finished and verified>
  - Not done: <what remains, and why it stopped>
  - Next command: <the exact command the next agent should run first>
  - Gotcha: <the trap that cost you time, or "none">
  ```

- `main` runs the full suite daily. The dominant risk with parallel agents is "every PR was green,
  the merge is red" — if the daily run breaks, fixing it outranks new work.

### Expert review roles

The full trigger table is appended by task `P0-10`. Until then, two rules already bind:

- **At most 2 expert roles per PR by default.** More reviewers per PR does not find more defects; it
  costs context and delays the merge.
- **Only deterministic scripts block CI.** LLM judgement is advisory: it is not reproducible and
  offers no appeal path, so it must never gate a merge. Anything worth blocking on must first be
  reduced to a script.

### CI budget

**Total PR gate wall time ≤10 minutes.** This is a hard constraint, not an aspiration. The concrete
mechanism by which infrastructure kills a project is: the gate gets slow → humans and agents start
skipping local verification → the gate stops catching anything. A PR that pushes the gate past 10
minutes must make it faster elsewhere in the same PR.

## Protected Files

Changing any path below requires the **Breaking Change process**: bump the affected version, write
the migration path into the PR description, and include the literal word `BREAKING` in the PR
description. Enforced by the `protected-files` CI job (`P0-09`); the job's list and this list must
match word for word.

| Path | Contract it encodes |
| --- | --- |
| `LICENSE`, `NOTICE` | Legal contract |
| `docs/adr/**` | Accepted architecture decisions. Adding a new ADR is unrestricted; **modifying or deleting an existing ADR** is not |
| `rust-toolchain.toml`, `rustfmt.toml` | Repository-wide toolchain and formatting contract |
| `docs/msrv.md` and every `rust-version` in `Cargo.toml` | The MSRV promise made to downstream users |
| `spec/ir.schema.json` | The frozen codegen IR. Every generated artifact is shaped by it; a change invalidates the samples and re-opens decisions P2–P10 already built on |
| `conformance/case.schema.json` | The frozen case format. Widening it late silently weakens every case already written against the narrower form |
| `model/s3.json`, `model/sts.json`, their `.sha256` sidecars, `model/PROVENANCE.md` | The pinned AWS service models. Re-pinning changes every generated artifact, so it is a reviewed protocol event, never a dependency bump |
| `crates/core/tests/golden/route-table.txt` | The resolved route table, in order. A diff here means some request now reaches a different operation than it did before — the one change that cannot be reviewed by reading the code that caused it |

| `model/overlays/**` | The only sanctioned hand-written protocol exception source. Quirks are hand-written, so they live here and **never** under the generated `spec/` tree |
| `spec/quirks/**` | Generated mutable protocol-rule table. Every entry names a typed current value and mutation dimension consumed by the mutation gate |
| `spec/contracts/**` | Generated non-codec contract table. Every entry must bind to an independently mutable runtime or emitter consumer; this is not a mutation exemption |

Overlay records without a typed current value and mutation dimension are deferred facts. They remain
in `model/overlays/**`, but are not generated into either protected rule table and do not count as
proved, wired, or complete.

**Pending — add the row the moment the path first exists, in the PR that creates it:**

| Path | Contract it encodes |
| --- | --- |
| The error-code → HTTP status mapping table | Externally observable API surface; clients branch on it |
| The public API snapshot | Semver contract for `rustfs-gateway` and every `s3gate-*` crate |
| Deletion of anything under `conformance/cases/**` | A deleted case is a silently dropped guarantee. Adding cases is unrestricted |

## Absolute Prohibitions

No exceptions. If you believe you have found one, stop and ask on the issue.

**Provenance**

- Never copy **code** from s3s into this repository — including its tests, CI workflows, and
  reporting scripts. Behavioural **facts** recorded in s3s issues and PRs may be used (facts are not
  copyrightable), but evidence is stored as **a URL plus one sentence you wrote yourself**. Pasting
  issue prose is forbidden; issue text stays under its author's copyright.
- Never paste AWS service documentation prose into this repository or into generated output.

**Code**

- Never commit a `.rs` file without the Apache-2.0 license header. Every Rust source file starts
  with this block verbatim, before the `//!` module docs (see `crates/core/src/lib.rs`),
  enforced by `scripts/check_license_headers.sh` (`P0-09`):

  ```rust
  // Copyright 2026 RustFS Team
  //
  // Licensed under the Apache License, Version 2.0 (the "License");
  // you may not use this file except in compliance with the License.
  // You may obtain a copy of the License at
  //
  //     http://www.apache.org/licenses/LICENSE-2.0
  //
  // Unless required by applicable law or agreed to in writing, software
  // distributed under the License is distributed on an "AS IS" BASIS,
  // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  // See the License for the specific language governing permissions and
  // limitations under the License.
  ```

  Shell scripts may carry the header but are not required to.
- No `unsafe`. The workspace sets `unsafe_code = "forbid"`; lifting it anywhere needs an ADR plus an
  explicit allowance list first.
- No `.unwrap()` / `.expect()` on anything that can fail from external input (requests, headers,
  bodies, config, filesystem, network). Test code is exempt; `expect` on a genuinely
  unrepresentable state is allowed only with a same-line comment stating why it cannot fail.
- Never write credentials, signatures, SSE-C keys, session tokens, or **expected** signature values
  into logs or error responses. "Expected vs actual" in an auth error is a signing oracle.
- Never compare signatures or key material with `==`. Use a constant-time comparison, and do not
  derive `PartialEq` on such types at all.
- No `#[non_exhaustive]` on DTO structs (see `P0-08` ADR-0004).
- No dependency on `inventory` or `linkme` (see `P0-07` ADR-0003). Registration must be explicit and
  greppable.

**Measurement**

This repository has now produced the same defect **seven times**: a check that cannot fail, which
reads exactly like a check that passed. Every one was found by accident. They are listed because
the list is the argument — no single instance looks like a pattern.

| # | What it was | What it meant |
|---|---|---|
| 1 | `inprocess` hard-coded `Outcome::Response` and `body_bytes_before_error: None` | every `stream_error` assertion went unevaluated, and `kind = "response"` was unfalsifiable — a 200 carrying an `<Error>` satisfied it |
| 2 | `request_progress` was a constant | "the body was not read" was always true |
| 3 | `sign_request` returned only headers | `c-sig-0001`'s query tampering was discarded; the case asserted against an **untampered** request |
| 4 | containment was judged on the unredacted body | no case looking for `__REDACTED__` could ever match |
| 5 | `setup.buckets.object_lock` was parsed and dropped | a declared precondition the backend never saw |
| 6 | `Transport::Conn` was an enum variant with no implementation | the report printed `transport conn` over a run that never opened a socket |
| 7 | `WireReject::must_close_connection` returned `true` with no branch, and `render` dropped it | two contract tests whose assertions could not have failed either way |

The rules that follow from it:

- **Never report an intention as an observation.** A response carrying `Connection: close` is not a
  closed socket. A service's own verdict is not a measurement of what the wire did. A note admitting
  the substitution does not change what a green line means to whoever reads the report.
- **A guard whose input is missing must fail, not skip.** `[[ -f x ]] || exit 0` is right when the
  input is a directory that may not exist yet and wrong when the input always exists.
- **Every new assertion owes a mutation.** Break the implementation on purpose and confirm the
  assertion goes red. If it does not, the assertion is decoration. Say in the PR which ones you
  mutated.
- **A one-directional control proves nothing.** An observer stuck on one answer satisfies every test
  that expects that answer. Prove both directions — a server that announces close and stays open
  **and** one that announces keep-alive and closes.
- **When a capability is missing, skip with the reason.** Failing for the wrong reason reads exactly
  like failing for the right one, and passing for the wrong reason is worse.

**Process**

- Never delete a test, weaken an assertion, or add `#[ignore]` to make CI green.
- Never use `git commit --no-verify`.
- Never commit in a shared checkout; one task, one worktree.
- **Never commit agent working notes, plan documents, or analysis reports.** The issue is the single
  source of truth (`P0-09` adds `check_no_planning_docs.sh`).
- Never refactor across a crate boundary without an ADR merged first.

## Dependency Boundaries

Three rings. **Ring 0/1 must never depend on any rustfs crate, and never on ring 2.** That is the
axiom that keeps `gateway → ecstore → dto types → gateway` from becoming a cross-repository cycle.
The rule has nothing to do with reuse — nothing here is published — and it survives the narrowed
scope untouched: `rustfs-gateway-types` is consumed by `rustfs/ecstore`, `lifecycle`, `replication`
and the scanner, while ring 2 depends on `ecstore`/`iam`/`policy`. One ring-0 edge back into rustfs
closes the cycle.

- **Ring 0/1 — protocol kernel**: every crate in this workspace. Zero rustfs dependencies.
  Membership is **declared** in `[package.metadata.gateway]`, not inferred from the crate name:
  after the rename every crate is `rustfs-gateway-*`, so the name carries no information.
- **Ring 2 — rustfs adapters**: `rustfs-gateway-*`. Not present in this workspace yet. Ring 2 may
  depend on ring 0/1 and on rustfs crates; the reverse is permanently forbidden.

`A ──▶ B` reads "A depends on B".

```
             rustfs-gateway-conformance          test-only product; runs against any S3 implementation
                    │
                    ▼
                 rustfs-gateway                  public facade: ServiceBuilder, hyper/tower adapters
                    │
                    ▼
              rustfs-gateway-core                Operation, route table, typed pipeline, extension traits
                    │
                    ▼
               rustfs-gateway-sig                SigV2/SigV4 state machine; freezes PayloadMode
                    │
                    ▼
              rustfs-gateway-http                wire layer: header/query views, limits, aws-chunked
                 │       │
                 ▼       ▼
        rustfs-gateway-types ──▶ rustfs-gateway-stream ──▶ http / bytes
                 │
                 ▼
           rustfs-gateway-xml ──▶ quick-xml

  build-time only, never present in a runtime dependency tree:
        rustfs-gateway-codegen ──▶ rustfs-gateway-model   codegen emits generated/**, spec/, OPERATIONS.md
        rustfs-gateway-xtask-dispatch (crates/xtask-dispatch)   std-only cargo xtask process selection

  runtime host, with no internal crate dependency:
        rustfs-gateway-server                    listener, TLS, hyper, admission, shutdown
        xtask ──▶ codegen + gateway/core + conformance   generation plus runtime diagnostics; build-time only
```

Three annotations you must not lose:

- **`rustfs-gateway-stream` exists to break a cycle.** `GetObjectOutput.body: StreamingBlob` would make
  `rustfs-gateway-types` and `rustfs-gateway-http` mutually dependent. `rustfs-gateway-stream` holds `Body`, `ByteStream`,
  `Payload`, and trailing-header typing, and **no S3 semantics whatsoever**. Do not put an S3 type
  in it.
- **Pipeline stage state is owned and `'static`.** The request carrier and its stage markers must
  not take lifetime parameters; borrowing a wire request across async stages creates a
  self-reference. Narrow proof and view values that are consumed within one stage are not stage
  state and may borrow their input.
- **`rustfs-gateway-sig` freezes `PayloadMode` before `rustfs-gateway-http` decodes chunked framing.** The framing
  mode is derived from the signature, not sniffed from the body. This is why the signature phase
  (P2) is numbered before the wire phase (P3).
- **The `compat-s3s` feature of `rustfs-gateway-types` is the only place a kernel crate may depend on s3s**
  (orphan rule, measured E0117: a third-party crate cannot write
  `impl From<s3s::X> for rustfs-gateway::X`). It must carry a `# DELETE BY <milestone>` marker.

Direction violations are hard-blocked by `scripts/check_layer_dependencies.sh` (`P0-09`).

## Context Budget & Do-Not-Read List

**Do not read these. Reading one destroys the rest of your session.**

| Path | Why | Read this instead |
| --- | --- | --- |
| `generated/**`, and its second name `crates/types/generated/**` | Generated code at s3s scale: `dto/generated.rs` alone is 39,374 lines, all `generated.rs` files total 73,019. Once 70k lines of it are in context, every `grep ETag` returns hundreds of noise hits and you can no longer locate anything. The second path is the ADR-0005 symlink onto `generated/dto` — same files, same rule | `OPERATIONS.md` for operation shapes |
| `model/s3.json` | 3MB. One read consumes the entire session budget | `spec/operations/*.toml`, which is generated from it |
| `Cargo.lock` | Large and information-free | `cargo tree -p <crate> -e normal` |

For field-level bindings read `spec/`; for operation shapes read `OPERATIONS.md`. These rules apply
before the paths exist — the first PR that generates `generated/**` must not be the PR where an
agent reads it.

**Context budget rules**

- A task's "read this and you can start" file set is **≤8 files / ≤40k tokens**. A task that cannot
  fit must be split. This is the test behind the `estimated context budget` field of the issue
  template — if you cannot fill that field honestly, the task is too big.
- Every crate root carries a `MAP.md` (≤100 lines): file → one-sentence responsibility → **when you
  would need to read it**. `MAP.md` is an agent entry point, not an architecture document for humans.
- Every source file opens with `//!` answering three questions: **what this file is responsible for
  / what it is explicitly not responsible for / who is upstream and downstream**. A file whose `//!`
  answers only the first question is incomplete.
- **Hard limit: 800 lines per file.** Over the limit, split it, or register an exemption in
  `docs/file-size-allowances.txt` with a reason. Large files are the number one context killer.

## One Operation Per File

> **The real value of one operation per file is that it is the unit of parallel edit conflict — not
> that it makes things easy to grep.**

Nobody ever failed to find `GetObject`. Even with 99 methods on a single trait, `grep get_object`
locates it. The actual payoff is that two agents changing two operations produce **zero git
conflicts**. Do not let a DRY argument overturn this rule without addressing that reason.

The counterweight is an **explicit shared contract**. Without it, the List/Copy/Conditional clusters
reproduce the s3s #499 vs #632 defect, where one rule lived in two places and two fixes contradicted
each other:

- `ops/<snake_name>.rs` contains exactly one `impl Operation`, and nothing else does.
- The file header declares its shared surface — `//! Shares: precondition, copy_source, pagination`
  — and may `use` only modules listed in `ops/shared/`.
- Every `ops/shared/**` module lists its member operations — `//! Members: ListObjects,
  ListObjectsV2, ...` — and the member set must agree with the actual `use` sites in both
  directions.
- The 800-line limit applies here too.

Known cross-operation clusters, for reference when you touch one of them:

| Cluster | Operations | Shared logic |
| --- | --- | --- |
| List | ListObjects, ListObjectsV2, ListObjectVersions, ListMultipartUploads | pagination, delimiter rollup, CommonPrefixes, encoding-type, continuation-token codec |
| Copy | CopyObject, UploadPartCopy | `x-amz-copy-source` parsing, copy-source conditional headers, source-resource extraction for two-stage authorization |
| Conditional | GetObject, HeadObject, CopyObject, PutObject | RFC 9110 precondition evaluation, strong/weak ETag comparison |
| ACL | Get/Put Bucket and Object ACL, canned ACL headers | grant parsing and canonicalization |
| Checksum | every operation accepting `x-amz-checksum-*` | header/trailer cross-validation |

`scripts/check_op_file_shape.sh` enforces this from P1; the rule binds now.

## Macro Governance

The `#[rustfs-gateway::handlers]` attribute macro is the single largest threat to agent comprehension: an
agent cannot answer "why is my method never called?" or "where did this trait bound come from?" when
the answer only exists after expansion. Four rules:

1. The macro performs **declarative registration only** — it registers functions into a registry. It
   must never rewrite a function body and must never mint a new public type name. A generated type
   name that `grep` cannot find blinds every agent instantly.
2. `cargo expand` goldens are checked in at `macros/tests/expand/*.expanded.rs`. An agent reads the
   expansion; understanding the macro is never a prerequisite.
3. A macro-free equivalent must exist and be documented side by side (`impl Handler<GetObject> for
   Fs`). The macro is permanently optional sugar, never the only path.
4. A test must prove the macro form and the hand-written form produce **identical registry
   contents**. The moment that equivalence breaks, the macro is broken.

## PR Checklist

- [ ] The four-command gate passed (fmt, clippy, test, `cargo xtask verify`)
- [ ] New or changed public API has rustdoc
- [ ] Negative test cases outnumber positive ones
- [ ] Every new assertion was mutated — the implementation was broken on purpose and the assertion
      went red. The PR description names which ones
- [ ] No Protected File touched; if one was, the PR description contains `BREAKING` and a migration path
- [ ] No `unsafe` introduced
- [ ] No `inventory` / `linkme` introduced
- [ ] No `#[non_exhaustive]` added to a DTO
- [ ] No s3s code copied; behavioural evidence is URL + self-written summary
- [ ] No credentials, signatures, or expected-signature values reachable from logs or error bodies
- [ ] No plan document, analysis report, or working note committed
- [ ] Commits follow Conventional Commits; PR title ≤72 characters
- [ ] A Handoff comment has been appended to the issue

## Common Errors and Fixes

| Wrong | Right |
| --- | --- |
| Test fails → change the assertion / add `#[ignore]` / delete the test | Fix the implementation. If the test really was wrong, explain in the PR description why the original assertion was incorrect |
| clippy complains → add `#[allow(...)]` | Fix the code. If an allow is genuinely required, a same-line comment must state why |
| Need logic in several operations → copy it three times | Extract into `ops/shared/`, and update both the `//! Shares:` and `//! Members:` declarations |
| Unsure about protocol behaviour → write it from memory | Check the AWS documentation and record URL + your own one-sentence summary as evidence |
| Want to record progress → create `PLAN.md` in the repo | Write it into the issue as a comment |
| Cannot find a type → `grep` the whole repository including `generated/` | Read `OPERATIONS.md` / `spec/`; `generated/**` is on the do-not-read list |
| New `.rs` file starts straight at `//!` | License header first, `//!` module docs second; `scripts/check_license_headers.sh` blocks the PR otherwise |
| Compare signatures with `==` | Constant-time comparison, and do not give the type `PartialEq` at all |
| Need a new crate-level rule → start a scoped `AGENTS.md` | Add it here, unless that crate already has 5 or more rules of its own |
| Gate got slower → accept it | Make it faster in the same PR; the gate budget is 10 minutes total |
| Harness cannot observe something → report the server's own intention instead | Report what was observed, or skip with the reason. A note admitting the substitution does not change what the green line means |
| A new assertion passes → assume it works | Break the implementation and confirm it goes red. Seven checks in this repository could not have failed |
| `cargo xtask verify --crate X` takes minutes → wait it out | Open an issue; the ≤30s loop is a contract, not a hope |

<!-- P0-10 appends: Expert Roles & Trigger Table -->
