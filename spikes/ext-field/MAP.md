# MAP — ext-field-spike

Agent entry point. File → responsibility → when you need to open it.

This unpublished spike measures one XML extension point. It is not a production codec and has no
runtime downstream consumer.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Shared bounded XML reader, events, errors, and writer helpers. | A resource limit or XML refusal changes. |
| `src/lifecycle_rule.rs` | Hand-written static parent codec and bounded body reader; it must not name the dialect type. | Q1, field ordering, or body reads change. |
| `src/policy.rs` | Runtime-owned registrations, vtables, three-state unknown policy, and typed extension storage. | Registration, dispatch, or miss semantics change. |
| `src/del_marker_expiration.rs` | The spike's only dialect field. | The single extension's typed body changes. |
| `tests/roundtrip.rs` | Five positive and five negative round-trip, dialect ordering, registry, atomicity, and real framework-request size cases. | Reviewing Q1, Q3, Q4, Q5, or Q6. |
| `tests/security.rs` | Six negative resource, DTD, entity, AST capability, dependency, and bounded-read cases. | Reviewing XML safety or transport limits. |
| `tests/unknown_elements.rs` | Five negative cases for lenient, allow-registered, deny, and persisted-data boundaries. | Reviewing Q2 or persisted configuration safety. |

## Verify

```bash
cargo test -p ext-field-spike
cargo clippy -p ext-field-spike --all-targets -- -D warnings
```
