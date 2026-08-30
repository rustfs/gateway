# MAP — rustfs-gateway-goldens

Agent entry point. File → responsibility → when you need to open it.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Runs fail-closed persistence compatibility assertions against independent old and new codecs. | Adding a configuration family or changing a D1-D5 assertion. |
| `src/object_lock.rs` | Binds Object Lock production/oracle codecs, enabled-decision projection, traceable samples, and mutations. | Auditing Object Lock persistence compatibility. |
| `src/lifecycle.rs` | Binds Lifecycle codecs, D1 structural evidence, D5 enabled decisions, traceable samples, parser boundaries, and mutations. | Auditing Lifecycle persistence compatibility. |
