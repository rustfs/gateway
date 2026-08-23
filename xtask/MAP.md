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
| `src/security_posture.rs` | Fail-closed dry-run preview derived from standard operation-floor sources. | The security-posture command or standard floor inventory changes. |
| `src/sigsuite.rs` | Pinned external signing-suite fetch and run process boundary. | Official signing-suite checkout or invocation changes. |
| `src/verify.rs` | Light crate verification and full operation/workspace verification selection; core compile-fail contracts stay in the full workspace gate. | A crate/op/all verification command is wrong. |
| `src/verify/process.rs` | Deadline-aware child supervision and output capture. | Verification children block, leak, or report out of order. |
| `src/verify/tests.rs` | Verification selection and scheduling unit contracts. | A bounded verification scope or schedule changes. |
| `src/why.rs` | Reverse trace and stable text/JSON rendering. | A `why` namespace or section changes. |
| `src/why/distance.rs` | Edit-distance ranking for nearby reverse-trace targets. | Unknown-target suggestions drift. |
| `src/why/error_code.rs` | Error-code status, producer and case reverse tracing. | The `why error-code` answer changes. |
| `src/why/tests.rs` | Pure completeness and exit-outcome controls. | The `why` completion rule changes. |
| `tests/integration.rs` | Single integration-test target registering all four test sources. | Add, remove, or rename an xtask integration test source. |
| `tests/cli_contract.rs` | Shared CLI output/exit contracts registered by `integration.rs`. | Change help or general process behavior. |
| `tests/why_contract.rs` | Six-namespace reverse-trace goldens registered by `integration.rs`. | Change `why` resolution or output. |
