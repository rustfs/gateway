---
name: gateway-adversarial
description: Run the RustFS Gateway expert-role probe playbook — protocol-auditor, security-adversary, simplicity-adversary, concurrency-durability, perf-engineer, test-adversary — with S3-specific attack probes (signature bypass, header injection, XXE, chunked-encoding boundaries, request smuggling, routing ambiguity, mid-stream stream errors). Use on every behavior-affecting change to this repository before declaring it done.
---

# RustFS Gateway Adversarial Review Playbook

This repository parses untrusted network input and verifies request
signatures. Both of those fail silently and expensively, so review here is
adversarial by default: a role does not read the diff looking for style, it
attacks the diff looking for a break.

This file holds the **probes**. The **policy** — which roles a given path
requires — belongs in the root `AGENTS.md` under
`## Expert Roles & Trigger Table`. Where the two disagree, `AGENTS.md` wins.
The condensed selection rules below exist so this skill is usable on its own,
not to create a second source of truth.

## The three layers, and why this skill is only the middle one

| Layer | What it is | Blocking? |
|---|---|---|
| 1 | Role duties that can be made deterministic, pushed down into `scripts/check_*.sh` | **Hard CI block** |
| 2 | Role duties that need judgement — **this skill**, run by the authoring agent in the same session | Not blocking; output goes in the PR |
| 3 | Parallel sub-agents, only for high-risk paths (signature/auth, wire parsing, routing pipeline) | Not blocking |

Two consequences worth internalising:

- **If a probe can be turned into a script, it must be.** A script is faster,
  cheaper, stable across runs, and can actually block a merge. Every probe
  below that becomes mechanical should be proposed as a new `check_*.sh` in
  `scripts/README.md`'s registry rather than repeated by hand forever.
- **LLM judgement never blocks CI.** It is unstable run to run and offers no
  appeal path. `check_role_verdicts.sh` will verify that verdicts *were
  written*, never that they were favourable — the author owns the content.

## Selecting roles (cost control)

A gate that costs too much gets switched off in week two, and a switched-off
gate is worse than no gate because everyone still believes it is running.
So the budget is part of the rules, not an afterthought:

1. **Default is at most 2 roles per PR**: `simplicity-adversary` (always) plus
   whichever single role the changed path selects.
2. More than 2 roles only when the changed path is one of the sub-agent rows
   in the `AGENTS.md` trigger table (`crates/http/**`,
   `crates/sig/**`), or the PR body is marked `HIGH-RISK`.
3. Role work for one PR is budgeted at **≤60k tokens**. Over budget, drop to a
   single-session skill pass instead of parallel sub-agents.
4. Documentation-only, comment-only and CI-config-only diffs need **no role**.

Condensed path map (authoritative copy lives in `AGENTS.md`):

| Changed path | Roles beyond `simplicity-adversary` |
|---|---|
| `docs/**`, comments, CI config | none |
| `conformance/cases/**` (added cases only) | `test-adversary` (light: is there a negative case?) |
| `model/**`, `spec/**`, `generated/**` | `protocol-auditor` |
| `crates/types/**`, `crates/xml/**` | `protocol-auditor`, `test-adversary` |
| `crates/http/**` (body, chunked, limits) | `security-adversary`, `concurrency-durability`, `perf-engineer` — sub-agents |
| `crates/sig/**` | `security-adversary`, `test-adversary`, correctness — sub-agents, high risk |
| `crates/core/**` (routing, pipeline) | correctness, `security-adversary` |
| `ops/**` | `protocol-auditor`, `test-adversary` |
| public API change (semver alarm) | `protocol-auditor` + mandatory human review |
| `compat-s3s`, dual-stack switches | migration safety + metadata golden |

## How to run a role

1. Start from the final diff and the nearest scoped `AGENTS.md`. Discard the
   assumptions of the session that wrote the code — that is the entire value
   of the pass.
2. Run the probes whose domain the diff touches, **plus any attack the diff
   obviously invites that no probe lists**. The playbook is a floor.
3. Report either a concrete failure scenario with `file:line`, or the role's
   null report naming what was attacked: *"attacked X, Y, Z — no break
   found"*. **A bare pass is not a result.**
4. Write findings into **one** PR comment covering all roles, and one line per
   required role in the PR description's `## Role Verdicts` block.
   **Never write a report file into the repository** —
   `check_no_planning_docs.sh` exists because agent reports that can land on
   disk accumulate until the repository is full of confident, stale analysis.

---

# Role playbooks

## 1. `protocol-auditor` — spec conformance and byte compatibility

Merged from the former `s3-spec-auditor` and `wire-compat-inspector`: on
encode/decode paths those two asked the same questions.

**Probes**

- **ETag quoting is per-operation, not global.** Find an operation where the
  diff emits a bare ETag and another where it quotes it, and check each
  against its evidence. A global rule here is always a bug.
- **`<Error>` has no `xmlns`.** Every other root element does. If the diff
  touched root-element emission, verify this exception survived.
- **Wire root element name vs. Rust type name.** They differ for several
  operations (aliases). Assert the wire name, never the type name.
- **Flattened vs. wrapped lists.** `<Contents>` repeated at the parent level
  is not `<Contents><member>`. Check every list the diff added.
- **Field order.** S3 clients that parse with a strict schema care. Compare
  against the recorded evidence, not against what looks tidy.
- **Four time formats.** `date-time` vs `http-date` vs epoch vs — critically —
  **`Expires`, which must be carried as an opaque string**, because real
  buckets contain unparseable values that AWS echoes back verbatim.
- **`encoding-type=url` scope.** It applies to a named subset of fields, not
  to the whole response.
- **Empty value: omit or emit?** The us-east-1 `LocationConstraint` is the
  canonical trap — an empty element and an absent element mean different
  things there.
- **`x-amz-storage-class` is omitted when `STANDARD`.**
- **Content-MD5 vs. `x-amz-checksum-*` precedence**, and the exact set of
  operations with `httpChecksumRequired`.

**Always ask:** *what is the evidence for this behaviour, and does the change
contradict an existing quirk?* An assertion with no evidence entry is a
finding on its own.

## 2. `security-adversary` — threat modelling and cryptography

Merged from `threat-modeler` and `crypto-auth-reviewer`, which overlapped
~80% on signature and auth paths.

**Signature and credential probes**

- **SignedHeaders coverage.** If `host` or any `x-amz-*` header is outside
  SignedHeaders, it can be injected unsigned. Concretely: an unsigned
  `x-amz-server-side-encryption-customer-key` or `x-amz-copy-source` turns a
  replayed signature into an attacker-chosen operation.
- **Credentials presented must be verified.** A malformed, expired or
  unparseable credential must be an error. **Never** degrade to anonymous —
  that converts an authentication failure into an authorization bypass on any
  bucket with a public policy.
- **Presigned URL lifetime** is capped at 604800 seconds; also check the
  lower bound and negative/overflowing values.
- **Clock skew** window is enforced on both sides, and the comparison does not
  wrap on far-future or pre-epoch dates.
- **Credential scope cross-check.** The scope's service and date must be
  validated *against the routed operation*, not merely parsed.
- **Privileged surfaces reject presigned auth entirely.**
- **Canonical host uses the raw request bytes.** If the canonical request is
  built from a normalised/lowercased/punycoded host, several distinct hosts
  map to one canonical string and one signature validates for all of them.

**Wire and parser probes**

- **Request smuggling.** `Content-Length` together with
  `Transfer-Encoding: chunked`; duplicate `Content-Length`; a chunk-size line
  with leading `+`, whitespace, or a `0x` prefix; a final chunk followed by
  trailing bytes; `aws-chunked` framing disagreeing with the outer HTTP
  framing.
- **Header injection.** CR/LF, NUL and non-ASCII in any header value that is
  echoed into a response header, an error message, or a log line.
- **XML attacks.** `<!DOCTYPE>`, external entities, entity expansion
  (billion-laughs), nesting depth, total body size, and element-count limits.
  Every one of these must have an explicit bound; "the parser probably handles
  it" is a finding.
- **Routing ambiguity.** A bucket named to look like a path prefix; a key that
  is `..`, `.`, empty, or percent-encoded to become one; virtual-host style vs
  path style resolving to different buckets for the same bytes. If two routes
  can claim one request, say which wins and why.
- **CORS preflight placement.** An unauthenticated `OPTIONS` that resolves
  CORS by looking up the bucket is both an unauthenticated storage amplifier
  and a private-bucket enumeration oracle (different response for exists vs.
  not-exists).
- **SSE-C.** Refuse over plaintext transport; the key must never appear in a
  response, a log line, an error, or a `Debug` output.
- **Two-phase authorization.** `UploadPartCopy` / `CopyObject` read a *source*
  resource; the source must be authorized before its bucket/key are read, not
  after.

**Always ask:** *given an attacker who knows a valid access key id but no
secret, what can they do — and what can they read that they should not?*

## 3. `simplicity-adversary` — the default role on every PR

This role exists because the framework has roughly a dozen extension points
(`SignatureVerifier`, `NameValidator`, `CodecPolicy`, `HostResolver`,
`PayloadSource`/`PayloadSink`, `Governor`, `Clock`, …) and **each currently
has exactly one implementation**. Nobody else is chartered to ask whether they
should exist. Abstraction explosion is not merely ugly here: it destroys the
property this project is built for, because an agent then has to read five
layers of trait indirection to find the code that actually runs.

**Probes**

- How many implementations does this trait have? If one — could it be a
  concrete type today, and become a trait when the second implementation
  actually appears?
- How many times is this generic parameter instantiated? One instantiation is
  a type alias wearing a costume.
- Does this layer of indirection answer a real, present requirement, or a
  hypothetical future one?
- Could this file be half its length? Could this new helper's single caller
  just inline it?
- Does this new public type have to be public? Public surface is a semver
  promise, and this project pays for those.
- Is this new constant/string literal already defined somewhere? Grep first.

**Always ask:** *if the abstraction were deleted, what would the code look
like — and in one sentence, what is worse about that version?* If the sentence
is hard to write, delete the abstraction.

**Hard criterion:** an abstraction with one implementation is an untested
abstraction. "Reserved as an RDMA extension point" and its relatives are not
acceptable — either produce a **second real implementation** that proves the
seam is in the right place, or remove the seam.

## 4. `concurrency-durability`

**Probes**

- **`CompleteMultipartUpload` must run in an independent task.** If the client
  drops the connection mid-completion and that cancels the completion, the
  upload is left half-committed. Dropping the body must not cancel the commit.
- **Timeouts must bound progress intervals, not total duration.** A total-time
  limit either kills legitimate large transfers or does nothing. Six distinct
  timers are needed: header read, first byte, body inter-read gap, handler,
  write progress interval, keep-alive idle. Check which one the diff meant.
- **Trailer timing must be in the type, not a mutex.**
  `Arc<Mutex<Option<Trailers>>>` lets a reader observe `None` before the
  trailers arrive and skip trailer-checksum validation *silently* — that is a
  security bug, not a race nit. `PayloadRead::Eof { trailers }` makes the
  ordering unrepresentable.
- **Cancel safety.** For each `await` the diff introduces: if the future is
  dropped here, what state is left behind — a half-written part, a held
  permit, a lock, a leaked temp object?
- **Backpressure and quota ownership.** Per-IP and per-connection limits must
  be released on every exit path, including the panicking and cancelled ones.

**Always ask:** *what happens if this future is dropped mid-flight?*

## 5. `perf-engineer`

Performance gates here **do not measure time**. Wall-clock assertions flake on
shared runners and get muted. Assert counts and sizes instead: allocations per
request, `const_assert!(size_of::<T>() <= N)`, and zero-copy behaviour
(a 1 GiB GET/PUT must assert `adapt_copies_total == 0`). Deterministic, no
flake, runnable anywhere.

**Probes**

- **`Req<O>` size.** Target ≤96 bytes: hot fields inline, everything else
  behind `Option<Box<ColdOpts>>`. The eleven checksum `Option<String>` fields
  collapse into one `ChecksumSpec { algo, [u8; 88] }`.
- **Where the generic boundary sits.** It must land exactly at
  `routed → decoded`. The first four pipeline stages stay non-generic;
  monomorphising them multiplies code size by the operation count.
- **Stage structs are owned and `'static`.** A lifetime parameter on a stage
  struct makes a borrowed body into a self-referential struct, which is how
  this design dies.
- **`max_chunk_size` has a default (1 MiB).** Unbounded chunk data size is a
  multi-gigabyte memory DoS from a single request.
- **`AdaptCost::Copy` is counted in a metric.** A copy that nothing measures
  is a copy nobody will ever remove.

## 6. `test-adversary`

**Probes**

- **Negative cases.** For every added positive case, is there a case asserting
  the *rejection* — malformed input, missing required field, wrong signature,
  over-limit body? A suite of happy paths measures nothing.
- **Boundary companions.** `n == max` and `n == max + 1`; empty vs. absent vs.
  null; zero-length body; the first and last part of a multipart upload.
- **Does the test fail if the fix is reverted?** If not, it is not a
  regression test. State explicitly which line it pins.
- **Mid-stream failure.** For streaming paths: does a test cover an error
  raised *after* bytes have already been written to the client? A silently
  truncated body that the client reads as a clean EOF is data corruption, and
  only an explicit test catches it.
- **Quirk coverage.** Every quirk needs at least one case referencing it, and
  every case at least one quirk or evidence entry. (`check_quirks_evidence.sh`
  will make this mechanical in P1 — until then it is this role's job.)
- **Determinism.** Any new test depending on wall-clock time, port allocation,
  filesystem ordering, or `HashMap` iteration order is a future flake; name it
  now.

**Always ask:** *what input would make this code wrong, and is that input in
the suite?*

---

## Deferred deterministic gates

These probes are meant to become scripts or CI jobs; until they do, the role
carries them by hand. Do not re-litigate the timing — it is set by dependency,
not preference.

| Gate | Replaces manual probes for | Blocked until |
|---|---|---|
| `difftest` job (byte-diff against s3s) | `protocol-auditor` wire compatibility | P5 — needs both stacks runnable |
| Mutation gate (`xtask conformance mutate`) | `test-adversary` quirk coverage | after P1 — needs ≥10 quirks |
| `cargo-semver-checks` + public-API snapshot | API ergonomics | first release |
| fuzz jobs | `security-adversary` parser probes | P2 (sig) / P3 (http) |
| Routing-ambiguity assertions | routing probes | P4 |
