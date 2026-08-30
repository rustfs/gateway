# MAP — rustfs-gateway-goldens

Agent entry point. File → responsibility → when you need to open it.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Runs fail-closed persistence compatibility assertions against independent old and new codecs. | Adding a configuration family or changing a D1-D5 assertion. |
| `src/accelerate_payment.rs` | Binds Accelerate and Request Payment production/oracle codecs, decision projections, traceable samples, and mutations. | Auditing Accelerate or Request Payment persistence compatibility. |
| `src/object_lock.rs` | Binds Object Lock production/oracle codecs, enabled-decision projection, traceable samples, and mutations. | Auditing Object Lock persistence compatibility. |
| `src/lifecycle.rs` | Binds Lifecycle codecs, D1 structural evidence, D5 enabled decisions, traceable samples, parser boundaries, and mutations. | Auditing Lifecycle persistence compatibility. |
| `src/notification.rs` | Binds Notification codecs, full routing decisions, traceable samples, parser boundaries, and D1-D5 mutations. | Auditing Notification persistence compatibility. |
| `src/bucket_encryption.rs` | Binds Bucket Encryption codecs, algorithm/KMS/bucket-key behavior, traceable samples, and mutations. | Auditing default-encryption persistence compatibility. |
| `src/public_access_block.rs` | Binds Public Access Block codecs, four-switch behavior, traceable samples, and mutations. | Auditing public-access persistence compatibility. |
| `src/cors.rs` | Binds CORS production/oracle codecs, full runtime projection, samples, parser boundaries, and mutations. | Auditing CORS persistence compatibility. |
| `src/tagging.rs` | Binds Tagging production/oracle codecs, complete tag projection, samples, parser boundaries, and mutations. | Auditing Tagging persistence compatibility. |
| `src/logging.rs` | Binds Bucket Logging codecs, delivery behavior, traceable samples, and mutations. | Auditing access-log configuration persistence. |
| `src/website.rs` | Binds Website codecs, routing behavior, traceable samples, and mutations. | Auditing static-website configuration persistence. |
| `src/replication.rs` | Binds Replication codecs, runtime rule projections, traceable samples, strict nested boundaries, and D1-D5 mutations. | Auditing Replication persistence compatibility. |
