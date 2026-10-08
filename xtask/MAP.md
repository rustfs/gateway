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
| `src/mutate/reach.rs` | `--reachability`: reruns a `SURVIVED` rule's mutated tree with coverage and judges its changed lines reached, unreached (`SURVIVED_UNREACHED`, a dead source) or unknown. | A survivor's reachability verdict, or the coverage collection, changes. |
| `src/mutate/report.rs` | Matrix row and summary wording, and the refinement of a `SURVIVED` row by a reachability answer. | A row's label or note changes. |
| `src/nested_cargo.rs` | Strips the `CARGO_MANIFEST_*` / `CARGO_PKG_*` variables `cargo run` gave xtask before any nested Cargo inherits them. | A nested Cargo rebuilds `ring` and everything above it that a shell build had already built. |
| `src/new_op.rs` | Intentionally-red operation scaffold. | Scaffold contents or collision checks change. |
| `src/route.rs` | Route explanation CLI rendering. | `route explain` output changes. |
| `src/rustfs_admin_dialect.rs` | `rustfs-admin-dialect [--check]`: chooses and rules the RustFS admin inventory's migrated routes (ADR-0025/0026/0028 action and subject rules, ADR-0027 templates and literal-over-parameter shadowing, ADR-0030 bucket bindings and trailing-slash templates, ADR-0031 surfaces with compat alias rows and first-divergence shadowing, ADR-0032 anonymous bootstrap opt-ins and staying routes), refuses any route it has no rule for and any rule outside those shapes, and writes or drift-checks `crates/dialect-rustfs-admin/src/{ops,table,table.rs}` through parallel rustfmt; `rulings.rs` holds the rulings, the query buckets and the staying routes, `rule.rs` the action rule and its shape check, `template.rs` reads templates, buckets, shadowing and names, `render.rs` emits the source with opaque admin captures (ADR-0040), `fallback.rs` emits the fixed authenticated fallback operations (ADR-0039), `form.rs` emits the form-claimed STS operation from its inventory row (ADR-0041, `form_tests.rs`), `tests.rs` holds the drift check and every refusal. | Migrating another admin group, adding a ruling or a query bucket, or a generated file drifted. |
| `src/route_contract.rs` | Bounded operation-route witness shared with the route CLI. | `verify --op` pulls in the production server graph or selects the wrong route. |
| `src/security_posture.rs` | Fail-closed dry-run preview derived from standard operation-floor sources. | The security-posture command or standard floor inventory changes. |
| `src/sigsuite.rs` | Pinned external signing-suite fetch and run process boundary. | Official signing-suite checkout or invocation changes. |
| `src/verify.rs` | Bounded crate/operation verification and full workspace verification selection; core compile-fail contracts stay in the full workspace gate. | A crate/op/all verification command is wrong. |
| `src/repo_root.rs` | Runtime discovery of the repository root from the process environment, never a compile-time path. | An xtask command reads the wrong checkout, or a sandbox-built binary names a directory that no longer exists. |
| `src/verify/prebuild.rs` | The build that runs ahead of a crate's 30-second deadline: the loop's own commands minus the run (`test --no-run`, each `clippy` step as itself), executed with no deadline, and the compiled-crate count. | A crate loop is charged for a build, or the prebuild selects the wrong targets. |
| `src/verify/budget.rs` | Budget-failure wording that keeps a killed loop apart from a timed one, and the note that attributes any crate a loop step compiled inside the budget, finished or killed, to the prebuild. | A budget failure is worded wrongly, or a build inside the budget is blamed on the crate. |
| `src/verify/full_gate.rs` | Full-gate stages run in order, each under its own deadline or the one the previous stage opened; every started stage is reported against its budget, and a kill or overrun is judged on the stage that had it. | `verify` or `verify --all` outlives a stage budget, blames the wrong stage, or reports the budget instead of a measurement. |
| `src/verify/full_gate/tests.rs` | Scripted-clock controls for per-stage and shared deadlines, overruns, stage order, descendant cleanup, and per-stage reporting. | A stage is charged for another stage's time, borrows time it was not given, or stops being attributed. |
| `src/verify/process.rs` | Deadline-aware child supervision against an injectable clock, and output capture. | Verification children block, leak, or report out of order. |
| `src/verify/process/lock_deadline_tests.rs` | Lock expiry after observed contention, independent of host scheduling. | A held lock hides an elapsed deadline or a deadline fixture mistakes a host pause for a failure. |
| `src/verify/process/grandchild_tests.rs` | Descendant cleanup measured after complete live PID publication, with delayed and missing-readiness controls. | A termination fixture expires before it can observe a descendant. |
| `src/verify/process/observation_tests.rs` | Live, stopped, and unreaped-child controls for the process-state observer. | A timeout test confuses a visible PID with an executing descendant. |
| `src/verify/process/path_isolation_tests.rs` | Unusable-PATH group termination, released only after the tree publishes a complete, live descendant pid. | A PATH-isolation case expires before its tree is observable, or group cleanup starts depending on PATH. |
| `src/verify/selection.rs` | Crate-local Cargo test and Clippy target selection. | A crate's bounded verification scope is wrong or too slow. |
| `src/verify/tests.rs` | Verification selection and scheduling unit contracts. | A bounded verification scope or schedule changes. |
| `src/why.rs` | Reverse trace and stable text/JSON rendering. | A `why` namespace or section changes. |
| `src/why/distance.rs` | Edit-distance ranking for nearby reverse-trace targets. | Unknown-target suggestions drift. |
| `src/why/error_code.rs` | Error-code status, producer and case reverse tracing. | The `why error-code` answer changes. |
| `src/why/tests.rs` | Pure completeness and exit-outcome controls. | The `why` completion rule changes. |
| `tests/integration.rs` | Single integration-test target registering all four test sources. | Add, remove, or rename an xtask integration test source. |
| `tests/cli_contract.rs` | Shared CLI output/exit contracts registered by `integration.rs`. | Change help or general process behavior. |
| `tests/why_contract.rs` | Six-namespace reverse-trace goldens registered by `integration.rs`. | Change `why` resolution or output. |
| `tests/bootstrap_diagnostics.py` | Actual bootstrap source exercised with fake child tools and codegen. | Stage timing or compiler diagnostics disappear without running a real workspace build. |
