# xtask crate map

Agent entry point for repository automation commands.

| File | Responsibility | Read it when |
|---|---|---|
| `src/main.rs` | Stable CLI dispatch and help. | Add or rename a subcommand. |
| `src/bootstrap.rs` | Bounded fresh-checkout preparation. | Bootstrap is slow or misses a prerequisite. |
| `src/catalog.rs` | Operation-to-crate verification map. | `verify --op` selects the wrong work. |
| `src/codegen.rs` | Codegen/spec command process boundary. | Generated verification reports wrongly. |
| `src/ir.rs` | Frozen IR validation command and shared schema diagnostics. | IR validation dispatch or positive goldens change. |
| `src/ir/negative.rs` | Exact negative corpus manifest and mutation runner. | Negative IR cases or expected diagnostics change. |
| `src/ir/semantic.rs` | Cross-field, shape, unwrapped-output, and quirk invariants. | A semantic IR rule changes. |
| `src/mutate.rs` | `conformance mutate`: the per-quirk kill matrix, and the guards that keep a mutation which never reached the gateway from reading as a gap in the corpus. | A mutation verdict, the inert/not-measured rules, or the restore loop changes. |
| `src/mutate/tests.rs` | Verdict-order controls for the mutation classifier, including the two shapes of ledger row that certify nothing (`UNWITNESSED`) and the live-case control that keeps `SURVIVED` meaning a corpus gap. | A guard in front of `SURVIVED` changes. |
| `src/new_op.rs` | Intentionally-red operation scaffold. | Scaffold contents or collision checks change. |
| `src/route.rs` | Route explanation CLI rendering. | `route explain` output changes. |
| `src/rustfs_admin_dialect.rs` | `rustfs-admin-dialect [--check]`: chooses and rules the RustFS admin inventory's migrated routes (ADR-0025/0026/0028 action and subject rules, ADR-0027 templates and literal-over-parameter shadowing, ADR-0030 bucket bindings and trailing-slash templates, ADR-0031 surfaces with compat alias rows and first-divergence shadowing, ADR-0032 anonymous bootstrap opt-ins and staying routes), refuses any route it has no rule for and any rule outside those shapes, and writes or drift-checks `crates/dialect-rustfs-admin/src/{ops,table,table.rs}` through parallel rustfmt; `rulings.rs` holds the rulings, the query buckets and the staying routes, `rule.rs` the action rule and its shape check, `template.rs` reads templates, buckets, shadowing and names, `render.rs` emits the source, `tests.rs` holds the drift check and every refusal. | Migrating another admin group, adding a ruling or a query bucket, or a generated file drifted. |
| `src/route_contract.rs` | Bounded operation-route witness shared with the route CLI. | `verify --op` pulls in the production server graph or selects the wrong route. |
| `src/security_posture.rs` | Fail-closed dry-run preview derived from standard operation-floor sources. | The security-posture command or standard floor inventory changes. |
| `src/sigsuite.rs` | Pinned external signing-suite fetch and run process boundary. | Official signing-suite checkout or invocation changes. |
| `src/verify.rs` | Bounded crate/operation verification and full workspace verification selection; core compile-fail contracts stay in the full workspace gate. | A crate/op/all verification command is wrong. |
| `src/repo_root.rs` | Runtime discovery of the repository root from the process environment, never a compile-time path. | An xtask command reads the wrong checkout, or a sandbox-built binary names a directory that no longer exists. |
| `src/verify/prebuild.rs` | The build that runs ahead of a crate's 30-second deadline: command derivation, execution with no deadline, and the compiled-crate count. | A crate loop is charged for a build, or the prebuild selects the wrong targets. |
| `src/verify/full_gate.rs` | Full-gate stages run in order under one shared deadline; the report names the stage that ran out and each finished stage's measured time. | `verify` or `verify --all` outlives its budget, blames the wrong stage, or reports the budget instead of a measurement. |
| `src/verify/full_gate/tests.rs` | Scripted-clock controls for the shared deadline, stage order, descendant cleanup, and stage attribution. | A full-gate stage stops sharing the deadline or stops being attributed. |
| `src/verify/process.rs` | Deadline-aware child supervision against an injectable clock, and output capture. | Verification children block, leak, or report out of order. |
| `src/verify/process/observation_tests.rs` | Live, stopped, and unreaped-child controls for the process-state observer. | A timeout test confuses a visible PID with an executing descendant. |
| `src/verify/selection.rs` | Crate-local Cargo test and Clippy target selection. | A crate's bounded verification scope is wrong or too slow. |
| `src/verify/tests.rs` | Verification selection and scheduling unit contracts. | A bounded verification scope or schedule changes. |
| `src/why.rs` | Reverse trace and stable text/JSON rendering. | A `why` namespace or section changes. |
| `src/why/distance.rs` | Edit-distance ranking for nearby reverse-trace targets. | Unknown-target suggestions drift. |
| `src/why/error_code.rs` | Error-code status, producer and case reverse tracing. | The `why error-code` answer changes. |
| `src/why/tests.rs` | Pure completeness and exit-outcome controls. | The `why` completion rule changes. |
| `tests/integration.rs` | Single integration-test target registering all four test sources. | Add, remove, or rename an xtask integration test source. |
| `tests/cli_contract.rs` | Shared CLI output/exit contracts registered by `integration.rs`. | Change help or general process behavior. |
| `tests/why_contract.rs` | Six-namespace reverse-trace goldens registered by `integration.rs`. | Change `why` resolution or output. |
