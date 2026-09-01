# MAP — rustfs-gateway-fs

Agent entry point. File → responsibility → when you need to open it.

| File | Responsibility | Read it when |
|---|---|---|
| `README.md` | Scope fence and supported-operation summary. | Deciding whether this reference backend fits a use case. |
| `src/lib.rs` | Filesystem paths, persistence, capability authority, and seven CRUD handlers. | Changing storage behavior or the registered operation set. |
| `tests/crud.rs` | Signed production-service CRUD and storage-boundary evidence. | Changing a handler, path rule, or public assembly API. |

## Verify

```bash
cargo xtask verify --crate rustfs-gateway-fs
```
