# Architecture guard scripts

Every file here named `check_<topic>.sh` is a deterministic guard: it takes no
arguments, prints a diagnostic to stderr when something is wrong, and **its
exit code is the verdict**. Each one can be run on its own:

```bash
scripts/check_layer_dependencies.sh
scripts/test_guard_scripts.sh          # runs the main guard suite and its negative cases
scripts/test_test_target_consolidation.sh # runs target-consolidation mutations in a parallel CI job
scripts/test_handlers_facade_fixture.sh # compiles the facade-only downstream macro fixture
GATEWAY_GUARD_QUIRK_LEDGER_ONLY=1 scripts/test_guard_scripts.sh # runs quirk-ledger mutations in a parallel CI job
GATEWAY_GUARD_JOBS=1 scripts/test_guard_scripts.sh # runs every case in one process, for debugging
```

`test_guard_scripts.sh` is split over four CI runners by `GATEWAY_GUARD_SHARD_GROUPS` /
`GATEWAY_GUARD_SHARD_GROUP`, and each runner splits its quarter again across worker
processes (one per core, capped at eight; `GATEWAY_GUARD_JOBS` overrides it). Each runner
proves afterwards that its workers executed exactly its own quarter, once each. It also watches its own clock against the
480-second budget CI gives it and stops with an explicit diagnosis rather than letting the
`timeout` wrapper kill it with an unexplained exit 124.

`run_gateway_tsan.sh` is the pinned-nightly a-asm-0024 execution command; it is a CI test rather
than a stable architecture guard.

`ci_budget.sh` runs one CI command under its wall-clock budget and reports the margin left over
**every run**, not only when the budget is blown:

```sh
scripts/ci_budget.sh 120 "target consolidation self-test" bash scripts/test_test_target_consolidation.sh
```

It exists because rustfs/gateway#188 and #217 were the same failure twice. A job grows with every
merge — AGENTS.md requires a mutation per new assertion, so case counts only go up — until it
crosses its hard `timeout`, and CI then prints `exit code 124` after every case has said `ok`. There
is no failing assertion to read and nothing names the clock, so the failure gets attributed to
whichever branch was next through the gate. #188 cost four pull requests a cycle each and one author
concluded their own work was broken; #217 sat red on main across three merges. Both times the margin
had been shrinking for weeks and nothing reported it.

So the wrapper prints `<label> completed in Ns of its Ms budget (P%)`, raises a `::warning::`
annotation past 80% of budget — visible on the pull-request checks UI, one PR early rather than on
the PR that crosses the line — and turns an overrun into an explicit `OUT OF TIME` diagnosis naming
the budget. `check_ci_test_split.sh` requires every timed command behind the `Test` aggregate to go
through it, so a new gate job cannot be added without a reported margin. A suite that can also watch
its own clock should still do so — `test_guard_scripts.sh` names the case in flight, which this
outer layer cannot — but the wrapper works for `cargo test` and everything else that will never
instrument itself.

## Conventions

These are binding for every script added here (rustfs/backlog#1723).

1. **Location and name.** `scripts/check_<topic>.sh`, executable, `#!/usr/bin/env bash`
   plus `set -euo pipefail`.
2. **Exit code is the verdict.** `0` = clean, non-zero = violation. No script
   may require a wrapper to interpret its output.
3. **Header comment is mandatory** and states three things:
   *what* it checks, *why* (with the issue or ADR that decided it), and
   *how to exempt* a case.
4. **Exemptions use the allowance-list pattern** borrowed from the rustfs/rustfs
   main repository (`check_unsafe_code_allowances.sh`): a plain-text file under
   `scripts/allowances/`, one entry per line, `#` for comments, each entry
   carrying a reason. Allowance files are hand-maintained and reviewed — there is
   deliberately no `--update-baseline` style regeneration flag, because a
   violation should cost a review, not one command. A guard treats a missing
   allowance file as an empty one, so none of them exist until they are needed.
5. **Root override.** Every guard honours `GATEWAY_CHECK_ROOT` so it can be run
   against a sandbox copy; this is what `test_guard_scripts.sh` uses.
6. **Only deterministic scripts may block CI.** LLM judgement (the expert roles
   in `.claude/skills/gateway-adversarial/`) produces verdicts, never a red
   build. See rustfs/backlog#1724.

`lib/cargo_deps.awk` is a shared helper, not a guard: it extracts declared
dependency names from a `Cargo.toml` so the three manifest-scanning guards agree
on what a "dependency" is.

## Registry

The full set of guards planned for this repository, with the phase each one
lands in. **Registration is not implementation** — names, scope and location are
fixed now so that the same check does not get written twice under two names.

### Implemented

| Script | Checks | Phase |
|---|---|---|
| `check_layer_dependencies.sh` | Internal crate dependency direction is one-way; the allow matrix is a DAG; `rustfs-gateway-conformance` may only use the facade; the stream kernel's normal/build dependencies stay on its reviewed external whitelist | P0 (Week-1, before P1) |
| `check_no_shared_trailers.sh` | Stream trailers are never stored behind a shared mutable optional slot; only EOF owns them | P1-05 |
| `check_no_as_any.sh` | Stream payloads expose no `as_any` or runtime downcast escape hatch | P1-05 |
| `check_stream_vocabulary.sh` | The stream kernel contains no S3 protocol vocabulary in source or comments | P1-05 |
| `check_pipeline_stage_shape.sh` | The real `RequestConfig` carrier owns its state and every state in its transition closure is a lifetime-free marker | P1-05 |
| `check_scalar_case_coverage.sh` | All 71 corrected P1-04 acceptance ids map to one atomic executable test or deterministic guard; the collided header-render case uses `c-etag-0101` | P1-04 |
| `check_etag_render.sh` | `ETag` has one contextual `render` entry and no `Display`, `From<ETag> for String` or `Into<String>` escape | P1-04 |
| `check_opaque_string.sh` | `OpaqueString` exposes no date/timestamp parsing convenience | P1-04 |
| `check_checksum_dependencies.sh` | `crc-fast` keeps default features off, enables only `std`, and is inherited by the types crate | P1-04 |
| `check_unsafe_code_allowances.sh` | The external crc-fast unsafe boundary has a reason/removal trigger and local Rust contains no unsafe token | P1-04 |
| `check_error_resolution_surface.sh` | ADR-0008 keeps one contextual HandlerError carrier, one ErrorResolution-to-S3Error bridge, no pre-resolution status writer, and HandlerError-only StageFilter seams | P1-04 |
| `check_scope_rejection_surface.sh` | ADR-0009 keeps configured scope remediation typed, canonically ordered, facade-private and separate from custom authenticator verdicts | P1-04 |
| `check_assembly_case_coverage.sh` | All 24 P7-01 acceptance ids map in order to a named executable test or deterministic guard | P7-01 |
| `check_ring_boundaries.sh` | Ring 0/1 (`rustfs-gateway*`) depends on no `rustfs-*` crate and no ring-2 `rustfs-gateway-*` crate; `s3s` only via `rustfs-gateway-types`' `compat-s3s` feature, which must keep its `# DELETE BY` marker | P0 (Week-1) |
| `check_no_planning_docs.sh` | Agent notes and planning documents are not tracked by git (closes the `git add -f` hole that `.gitignore` leaves open) | P0 |
| `check_protected_files.sh` | Existing contract paths, `rust-version`, and deleted conformance cases require a literal `BREAKING` declaration in the PR body; new ADRs and cases remain unrestricted | P0-09 |
| `check_no_global_registry_deps.sh` | No `inventory` / `linkme` / `ctor` dependency in any `Cargo.toml` (ADR-0003) | P0-07 |
| `check_macro_governance.sh` | The handler macro keeps adjacent macro-free docs, no link magic, no minted public types, unchanged method bodies, and registry equivalence | P4-07 |
| `check_ct_eq.sh` | Secret-bearing types (`Signature`, `Secret`, `SigningKey`, …) derive no `PartialEq` / `Eq` / `Debug`; every hand-written `PartialEq` calls `::subtle::ConstantTimeEq::ct_eq`; aliases and look-alike helpers cannot restore ordinary equality | P0 (before P2) |
| `check_role_verdicts.sh` | PR bodies record each path-triggered advisory role with substantive evidence; deterministic presence is enforced but verdict judgement never blocks CI | P0-10 |
| `check_license_headers.sh` | Every tracked `.rs` file opens with the Apache-2.0 licence header (ADR-0001 provenance boundary) | P0 |
| `check_governance_attribution.sh` | The s3s relationship statement and adapted aws-sigv4 helpers retain their reviewed source, revision, licence, and copied-code registry entry | P0-01 |
| `check_smithy_timestamp_corpus.sh` | The vendored Smithy timestamp corpus matches its pinned bytes, case counts, license attribution, and format mapping | P1-04 |
| `check_has_operation_coverage.sh` | Every code-generated standard operation name has exactly one matching per-operation `HasOperation` reverse mapping | P1-07 |
| `check_op_file_shape.sh` | One `impl Operation` per `ops/<snake_name>.rs` and none outside it; the file name and the operation name agree; `ops/mod.rs` mounts every module; the `//! Shares:` declaration agrees with both the `shared::` use graph and the `//! Members:` list on the other end, in both directions for both; 800 lines over the ops tree with no allowance escape | P1 (rustfs/backlog#1895) |
| `check_shared_members.sh` | Every `ops/shared/*.rs` module's `//! Members:` line agrees with the operations that actually reach it, in both directions | P1 |
| `check_shared_reachable.sh` | Every `pub` item under `ops/shared/` is re-exported by the `rustfs-gateway` facade, so a backend cannot be forced to reimplement a shared contract | P1 |
| `check_guard_grep_pipelines.sh` | The license and secret-hygiene guards contain no quiet grep option token, including in comments or strings; their grep checks must read input fully under `pipefail` | P0 |
| `check_english_only.sh` | No tracked file contains CJK text. `rustfs/backlog` is the one repository in the organisation where Chinese is allowed; this is not it. Matches by codepoint in Python — a grep bracket range is read by locale collation and flags an em dash | P0 |
| `check_ci_time_gate.sh` | Every PR job has a timeout, every dependency path stays within ten minutes, and Static checks / Clippy / Test retain their exact branch-protected contract | P0-04 |
| `check_ci_annotation_integrity.sh` | No author-controlled webhook text reaches the CI log unencoded, where the runner would read a leading `::` as a workflow command; the pull-request body is exported through `toJSON(...)`, both consumers refuse a body that is not one JSON line, and the guard proves both directions against a control that renders the same fixtures the vulnerable way | rustfs/gateway#224 |
| `check_template_contract.sh` | Four issue templates, their enabled contact configuration and the PR template retain structured headings, stable gate anchors and byte-matched AGENTS checklist items | P0-05 |
| `check_adr_contract.sh` | ADR names, continuous numbering, metadata, five-section shape, supersession backlinks and the hand-maintained README index form one structured record | P0-06 |
| `check_generated_dto_packaged.sh` | Every `#[path]` under `crates/*/src` stays inside its crate, reaching the generated dto through the `crates/types/generated` symlink | P1-06 |
| `check_no_dto_non_exhaustive.sh` | No generated dto struct carries `#[non_exhaustive]`; it forbids `..Default::default()` (E0639), which is the very syntax that keeps a new field minor (ADR-0004 P1) | P1-06 |
| `check_no_exhaustive_destructuring.sh` | No hand-written code destructures a dto without a trailing `..`; that is the one pattern a new field breaks (ADR-0004 P3) | P1-06 |
| `check_dto_fields.sh` | DTO public field count only grows (the `non_exhaustive` and destructuring halves are now implemented separately, see above) | P0-08 |
| `check_operation_spec_builder.sh` | `OperationSpec` construction stays on its additive builder — only the E0639 compile-fail fixture uses a literal — and inside `crates/core/src/ops/**` it uses `OperationSpec::standard`, so a standard operation cannot restate a status or an unconfigured code the overlay declares | P1-06 |
| `check_version_metadata.sh` | The types crate version carries a valid `+aws.YYYY-MM-DD` model date and keeps the workspace numeric version | P1-06 |
| `check_resolver_pure.sh` | `HostResolver::resolve` is synchronous and awaits nothing, no implementation holds a store handle, `HostQuery` declares exactly `host`/`path`/`method`, and no resolver code names a forwarded header. The resolver answers before authentication, so all four are amplification and enumeration properties rather than tidiness | P6-04 |
| `check_no_minio_source.sh` | Clean-room provenance: no AGPL licence text outside `scripts/allowances/clean-room-allowances.txt`, no comment claiming a port from MinIO or Garage, no vendored server tree or Go source, no `minio/minio` submodule or dependency. Rules 2-4 are not exemptable; the guard self-test caps scanner process counts and rejects literal absolute scanner paths so repository scans stay batched | P6-08 |
| `check_sse_key_never_leaks.sh` | The SSE-C customer key never leaves: no operation *output* binds a key header, the response invariant still strips both spellings, `KeyText::expose` has one call site, the SSE module has one `subtle::Choice`-to-`bool` conversion, and no formatting or logging macro names a customer key | P6-06 |
| `check_authz_consumption.sh` | Dispatch accepts only `Authorized<O>`; the authorization proof types have no public constructor; every operation explicitly declares derived resources | P4-05 |
| `check_authz_fail_closed.sh` | Authorization has exactly three decisions; only core settles them; denial is always AccessDenied; audit sinks cannot answer; examples contain no allow-all shortcut | P6-02 |
| `check_policy_snapshot_once.sh` | The service reads policy exactly once before either mandatory authorization stage | P6-02 |
| `check_authz_no_default_impl.sh` | Both `Authorizer` stages exist and neither has a default method body | P6-02 |
| `check_no_allow_all_in_examples.sh` | Rust examples contain no unconditional allow authorizer | P6-02 |
| `check_no_scaffold_on_main.sh` | No tracked or untracked `new-op` artefact retains the `SCAFFOLD: implement before merge` marker | P7-06 |
| `check_verify_map_generated.sh` | The operation-to-test map is codegen-owned and byte-for-byte current, never hand-maintained | P7-06 |
| `check_tool_versions_pinned.sh` | Six CI Cargo tools have one central exact version pin; no moving `latest` or `cargo-binstall` installer | P7-06 |
| `check_rust_toolchain_msrv.sh` | Cargo MSRV, exact development toolchain, documentation and every CI job agree on one compiler; no job installs a moving channel | P0-02 |
| `check_xtask_codegen_surface.sh` | Codegen and exact crate verification use a bounded light dependency surface while operation, workspace and unknown commands retain the full xtask surface | #60 |
| `check_map_files.sh` | Every workspace package has a bounded three-column MAP, docs.rs metadata and README-backed crate docs; maps never recommend forbidden inputs | P7-05 |
| `check_module_doc.sh` | Every hand-written Rust file answers responsibility, non-responsibility and upstream/downstream in its opening docs | P7-05 |
| `check_file_size.sh` | Hand-written Rust files stay within 800 lines or a reasoned, issue-linked allowance | P7-05 |
| `check_agents_forbidden_list.sh` | The three context-budget prohibitions each retain a reason and safe alternative | P7-05 |
| `check_agents_context_contract.sh` | The root task-start context budget remains bounded at 8 files and 40k tokens | P0-03 |
| `check_agents_layering.sh` | Scoped AGENTS files wait for the five-rule trigger and duplicate checker | P7-05 |
| `check_config_load_once.sh` | `c-lim-0005` binds one request to one hot-config snapshot; `c-lim-0041` freezes every `.load()` / `.load_full()` call site at request entry | P3-05, P7-01 |
| `check_chunk_limits.sh` | `c-lim-0042` binds a four-GiB chunk to header-time refusal and an instrumented peak-RSS increase below eight MiB | P3-05 |
| `check_missing_content_length.sh` | `c-lim-0020` / `c-lim-0022` bind an unframed non-streaming PutObject to 411 `MissingContentLength`, zero trailing bytes sent before the answer, and an observed socket close | P3-05 |
| `check_declared_body_limit.sh` | `c-lim-0021` binds an oversized declared body to an immediate 400 `EntityTooLarge` and an observed socket close without sending the body | P3-05 |
| `check_governor_fast_path.sh` | `c-lim-0004` binds an admitted request to the synchronous Governor path and structurally rejects allocation operations there | P3-05 |
| `check_default_doc.sh` | Every public extension `Default` implementation states its security consequence; derived subjects are discovered rather than listed by hand | P7-01 |
| `check_minimal_assembly_lines.sh` | The complete assembly in the minimal example stays within twenty effective Rust lines | P7-01 |
| `check_gateway_tsan_wiring.sh` | The TSAN job keeps sanitizer/build-std flags, runs in required CI, and drives exactly 100 completed OS threads | P7-01 |
| `check_monomorphic_dispatch.sh` | The public static assembly emits direct operation codec and concrete handler calls, with no erased dispatch callback in that call chain | P7-01 |
| `check_handler_context_migration.sh` | Reviewed handlers keep legacy `call` beside an explicit `call_with_context`; core wrappers also retain the framework cancellation source through delegation | P3-03 |
| `check_handler_deadline_class.sh` | Every standard operation has one explicit closed handler-deadline class; unknown operations receive no implicit class | P3-05 |
| `check_schema_dimensions.sh` | The frozen conformance schema retains all nine P8-01 day-one expression dimensions | P8-01 |
| `check_evidence_shape.sh` | Every case has compact HTTPS/URN-plus-summary evidence and cannot carry pasted upstream prose | P8-01 |
| `check_baseline_ratchet.sh` | The conformance baseline failure set only shrinks | P8-01 |
| `check_runner_raw_bytes.sh` | Case requests retain a raw TCP byte path and acquire no normalizing client dependency | P8-01 |
| `check_guard_sandbox_archive.sh` | Guard sandboxes use a temporary archive file; archive creation and extraction fail closed and clean partial state | P0 |
| `check_sig_case_coverage.sh` | All 163 P2-01 through P2-05 signature cases map to named executable evidence | P2-01 through P2-05 |
| `check_test_target_consolidation.sh` | Core, gateway and conformance integration sources each remain one explicit Cargo target, with gateway compile-fail fixtures sharing one trybuild batch | P0-04 |
| `check_xtask_test_target_consolidation.sh` | All four xtask integration sources remain active and unique in one explicit Cargo target | P0 |
| `check_sig_test_target_consolidation.sh` | All nine sig integration sources remain active and unique in one explicit Cargo target | P0 |
| `check_test_target_coverage.sh` | Every workspace member shipping integration tests is either held in one target by a named consolidation guard or carries an exception row with its target count, a tracking issue and a reason; the counts are a ratchet | P0-04 |
| `check_no_host_normalize.sh` | Ring-1 server source never mutates Host or URI authority | P7-02 |
| `check_timeout_layer_ownership.sh` | Server owns three of six idle-timeout layers; `c-lim-0032` binds the ten-second slow-header close; `c-lim-0037` holds per-IP rejection and other-IP p99 under ten thousand half-open attempts; connection lifetime remains a separate safety valve; `c-lim-0061` keeps the write-progress layer's thousand-slow-reader closure, healthy p99 and resident-memory evidence executable | P3-05, P7-02 |
| `check_tuning_doc.sh` | Every server tuning field documents both directions of its tradeoff | P7-02 |
| `check_fuzz_targets_registered.sh` | Every `fuzz/fuzz_targets/*.rs` has a matching `[[bin]]`, every `[[bin]]` names a file that exists, and every target still declares `#![no_main]` and invokes `fuzz_target!` | P4-01 |
| `check_operations_json_fields.sh` | `generated/OPERATIONS.json` carries all seven wire fields per operation in order, one reverse index per field, each index exactly the inverse of the forward table in both directions, and the same operation set as `OPERATIONS.md` | P4-01 |
| `check_route_shadowing_authority.sh` | `model/overlays/route.toml` is the only source of cross-precedence route shadowing: every pair carries a reason and evidence, no `ShadowingDecl` is hand-written under `crates/core/src`, and the generated record matches the overlay pair for pair | P4-01 |
| `test_test_target_coverage.sh` | Not a guard: mutates the workspace skeleton and the coverage tables and asserts `check_test_target_coverage.sh` goes red on each | P0-04 |
| `test_guard_scripts.sh` | Not a guard: runs every guard on the tree and asserts each one fails on an injected violation | P0 |
| `test_handlers_facade_fixture.sh` | Not a guard: compiles a downstream Cargo fixture whose only dependency is `rustfs-gateway` | P4-01 |
| `test_sig_case_coverage.sh` | Not a guard: isolates the P2-02 and P2-05 signature coverage mutations from the central guard self-test | P2-02, P2-05 |

### Registered, not yet implemented (TODO)

| Script | Checks | Phase |
|---|---|---|
| `check_ci_time_gate.sh` | Total PR gate wall time stays inside the 10-minute budget | P0-04 |
| `check_role_verdicts.sh` | High-risk PR descriptions carry the required expert-role verdicts (PR-only job; needs the `## Role Verdicts` anchor from the PR template) | P0-10 |
| `check_quirks_evidence.sh` | Every quirk has ≥1 evidence and ≥1 case referencing it, consistent in both directions | P1 |
| `check_quirk_ledger.sh` | Every typed quirk joins its generated constant to one production consumer and bilateral executable case evidence. For a **mutable** rule the join is a claim by an operation overlay, not proof that running code reads the lowered value — `cargo xtask conformance mutate` is the half that can answer that | P1, P2 |
| `check_error_status_total.sh` | The error code to HTTP status mapping has one hand-written authority, covers every code an operation can produce, keeps the 5xx band to an explicit allowlist in both directions, and carries no row nothing reaches | P4-02 |
| `check_error_codes_json_fields.sh` | `generated/error_codes.json` carries all three fields per code in order, one reverse index per field, each index exactly the inverse of the forward table in both directions, the same codes and values as `generated/ERROR_CODES.md`, and a `server_fault` set equal to the 5xx band | P4-02 |
| `check_error_contract_ledger.sh` | Every one of the 24 acceptance ids in rustfs/backlog#1694 §7 maps to a resolved assertion in a case, a Rust test or a replayed guard mutation, or to a block with the issue that owns it; the 9/15 polarity split and each named case's declared polarity are pinned with it | P4-02 |
| `check_error_has_rule_ref.sh` | Diagnostic errors carry a rule reference (quirk id / RFC section / spec field path) | P2 |
| `check_wire_boundary.sh` | Wire-layer boundary constraints | P3 |
| `check_form_limits.sh` | The six POST Object form cases each name one active test; `FileReader` has one door and it takes a byte ceiling, composed with the deployment maximum by `min`; `FormLimits` grows no unlimited constructor | P3-05 |
| `check_governor_position.sh` | `c-lim-0039` fixes `Governor::try_acquire` after routing and before body reads; `c-lim-0040` observes a 503 with zero body reads | P3-05 |
| `check_no_header_unwrap.sh` | Header parsing never `unwrap`s | P3 |
| `check_no_duplicate_fuzz_targets.sh` | Fuzz targets are not duplicated between P2-07 and P8-07 | P8-07 |
| `check_agents_no_dup.sh` | Scoped `AGENTS.md` files do not restate root rules | Deferred until layered `AGENTS.md` files exist |

## Scalar fuzz entry points

P1-04 registers `etag_parse` and `range_parse` in `fuzz/Cargo.toml`. Their acceptance run is
`cargo fuzz run <target> -- -runs=200000`; registration alone is not recorded as a completed run.
