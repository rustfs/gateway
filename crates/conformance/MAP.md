# rustfs-gateway-conformance crate map

Agent entry point for the data-driven conformance runner. Design reasons live in module docs and
ADRs; this map only selects files.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and public runner surface. | Start here for a conformance task. |
| `src/main.rs` | CLI arguments and process exit classes. | The binary accepts or reports an option incorrectly. |
| `src/corpus.rs` | Corpus discovery, loading and selection. | A case is missing, duplicated or filtered wrongly. |
| `src/schema.rs` | Frozen schema validation. | A TOML shape is accepted or rejected incorrectly. |
| `src/toml.rs` | Minimal TOML value parser used by the corpus. | Syntax parsing fails before schema validation. |
| `src/runner.rs` | Case/exchange execution order and timeout coordination. | A case runs in the wrong order or never reaches a verdict. |
| `src/expect.rs` | Expected observation matching. | A response, stream error or timing assertion is judged wrongly. |
| `src/inprocess.rs` | In-process facade transport. | Hyper-independent execution differs from the socket path. |
| `src/observation.rs` | Response and event-stream observations, including frame validation. | An event-stream case is classified incorrectly. |
| `src/socket.rs` | Real socket transport and connection observations. | A wire-level close/reuse fact is wrong. |
| `src/conn/` | Connection state and reusable transport helpers. | A multi-exchange case loses connection state. |
| `src/sign.rs` | Request signing for corpus inputs. | A signed case sends the wrong request. |
| `src/fixture.rs` | Deterministic fixture backend used by local runs. | Setup state or a fixture operation behaves wrongly. |
| `src/keys/` | Schema-key consumption audit. | A declared case key is parsed but ignored. |
| `src/report.rs` | Human, JSON and JUnit reports. | A verdict is rendered or grouped wrongly. |
| `src/baseline.rs` | Baseline comparison. | Known failures or regressions are classified wrongly. |
| `src/lint.rs` | Corpus conventions beyond the JSON schema. | Case naming or evidence lint fails. |
| `tests/` | Process and corpus integration contracts. | Change runner behavior or CLI output. |
| `../../conformance/cases/**` | Executable S3 behavior cases. | Add or diagnose one protocol behavior. |
| `../../conformance/case.schema.json` | Frozen case format. | Never edit without the Breaking Change process. |
