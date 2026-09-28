# MAP — rustfs-gateway-corpus-recorder

Agent entry point. File → responsibility → when you need to open it.

Everything below `src/lib.rs` compiles only with the `corpus-record` feature. That is the
compile-time line of defence; do not move an item out from behind it.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | The feature gate and the public surface. | Start here; a symbol shows up in a build without the feature. |
| `src/config.rs` | `RecorderConfig`, the test-credential allowlist, and the runtime refusal. | The recorder starts when it must not, or refuses when it should start. |
| `src/layer.rs` | The tower `Layer`/`Service`, the checked constructor, request and response head capture. | Mounting it, or an entry's head or response is wrong. |
| `src/body.rs` | The passive body tap and the per-request capture that becomes a record. | The inner service sees a different body, or a body is recorded when it was not observed whole. |
| `src/classify.rs` | Naming the operation with the gateway's generated route table. | An entry lands under the wrong operation, or is counted as unrouted. |
| `src/writer.rs` | Bounded queue, writer thread, the corpus gate before disk, the counters. | Something reached the file that should not have, or a request was slowed by recording. |
| `tests/recorder/gate.rs` | Runtime gate refusals. | Changing `config.rs`. |
| `tests/recorder/capture.rs` | Pass-through identity, redaction before disk, the no-write refusals. | Changing `layer.rs`, `body.rs` or `writer.rs`. |
| `tests/recorder/signed_chunks.rs` | A real signed-chunk upload through `S3Service`, recorded and ingested. | Anything touching framing or the ingest contract. |
| `tests/recorder/symbols.rs` | No recorder symbol in a build without the feature, with its control. | Changing the feature gate. |
| `README.md` | The three lines of defence and the RustFS integration steps. | Integrating the recorder into a host. |
| `../../scripts/check_recorder_not_default.sh` | The feature stays out of every `default` set and every non-optional edge. | That guard fails. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-corpus-recorder
bash scripts/check_recorder_not_default.sh
```
