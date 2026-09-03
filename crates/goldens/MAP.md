# MAP — rustfs-gateway-goldens

Agent entry point. File → responsibility → when you need to open it.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Runs fail-closed persistence compatibility assertions against independent old and new codecs. | Adding a configuration family or changing a D1-D5 assertion. |
| `src/acceptance_census.rs` | Binds the exact 39 P9-01 IDs to runtime or pinned external evidence without counting blockers as passing. | Auditing final case closure, blocker disposition, or census mutations. |
| `src/corpus.rs` | Derives coverage from concrete traceable accepted/rejected samples without claiming aggregate completeness. | Wiring family-owned sample collections or changing corpus validation. |
| `src/provenance.rs` | Names the four approved persisted-metadata sources, requires writer name plus exact version on the (c)/(d′) tiers, and fails closed by name while an approved source is absent. | Registering a collected source, auditing writer provenance, or asking why closure is still held. |
| `src/corpus/backup_zip.rs` | Proves old/new backup archives preserve every accepted persisted XML byte and remain readable in both migration directions. | Auditing backup import/export rollback evidence or its fail-closed archive checks. |
| `src/source_a_boundary.rs` | Binds the four physical CORS and Lifecycle rule-cap fixtures to exact source-(a) paths, case IDs, and SHA-256 digests. | Auditing physical fixture census or rule-count boundary migration evidence. |
| `src/source_a_census.rs` | Fails closed unless all 38 audited source-(a) references map to the exact 30 kind/digest/disposition corpus registrations and sample/alias roles. | Auditing aggregate source-(a) completeness or adding a physical RustFS fixture binding. |
| `src/source_a_lifecycle.rs` | Registers one unique RustFS Lifecycle metadata-test literal and two exact marshal provenance aliases. | Auditing source-(a) Lifecycle byte identity or alias deduplication. |
| `src/source_a_new_writer.rs` | Binds selected RustFS CORS and Lifecycle `NEW_WRITER_CONFIGS` bytes to exact source references and SHA-256 digests. | Auditing source-(a) new-writer rollback fixtures or their census. |
| `src/source_b_mc.rs` | Registers official-mc CORS and Lifecycle raw exports plus a deduplicated Versioning provenance alias. | Auditing the live mc client matrix, raw metadata digests, or alias census. |
| `src/source_b_rclone.rs` | Binds rclone's only supported bucket-configuration capture as a deduplicated Versioning provenance alias. | Auditing rclone client capability evidence, raw metadata identity, or alias census. |
| `src/bin/corpus-report.rs` | Validates and renders all persisted XML corpus families plus the approved-source census, with fail-closed process status. | Running or changing the persistence corpus CLI. |
| `src/bin/four-way.rs` | Executes all persisted XML samples through D1-D5 with a fail-closed process status. | Running or changing the full persistence rollback gate. |
| `src/accelerate_payment.rs` | Binds Accelerate and Request Payment production/oracle codecs, decision projections, traceable samples, and mutations. | Auditing Accelerate or Request Payment persistence compatibility. |
| `src/versioning.rs` | Binds Versioning codecs, concrete accepted/refused corpus rows, runtime behavior, and D1-D5 mutations. | Auditing Versioning persistence compatibility or its corpus coverage. |
| `src/object_lock.rs` | Binds Object Lock production/oracle codecs, enabled-decision projection, traceable samples, and mutations. | Auditing Object Lock persistence compatibility. |
| `src/lifecycle.rs` | Binds Lifecycle codecs, D1 structural evidence, D5 enabled decisions, traceable samples, parser boundaries, and mutations. | Auditing Lifecycle persistence compatibility. |
| `src/lifecycle/source_b.rs` | Registers the byte-exact Lifecycle sample captured through the live source-(b) client path. | Auditing the boto3-to-RustFS persistence provenance for Lifecycle. |
| `src/notification.rs` | Binds Notification codecs, full routing decisions, traceable samples, parser boundaries, and D1-D5 mutations. | Auditing Notification persistence compatibility. |
| `src/notification/corpus_cases/source_a.rs` | Pins RustFS repository Notification fixture bytes, aliases, old-oracle classification, and provenance. | Registering or auditing Notification source-(a) census rows. |
| `src/bucket_encryption.rs` | Binds Bucket Encryption codecs, algorithm/KMS/bucket-key behavior, traceable samples, and mutations. | Auditing default-encryption persistence compatibility. |
| `src/public_access_block.rs` | Binds Public Access Block codecs, four-switch behavior, traceable samples, and mutations. | Auditing public-access persistence compatibility. |
| `src/cors.rs` | Binds CORS production/oracle codecs, full runtime projection, samples, parser boundaries, and mutations. | Auditing CORS persistence compatibility. |
| `src/tagging.rs` | Binds Tagging production/oracle codecs, complete tag projection, samples, parser boundaries, and mutations. | Auditing Tagging persistence compatibility. |
| `src/logging.rs` | Binds Bucket Logging codecs, delivery behavior, traceable samples, and mutations. | Auditing access-log configuration persistence. |
| `src/website.rs` | Binds Website codecs, routing behavior, traceable samples, and mutations. | Auditing static-website configuration persistence. |
| `src/replication.rs` | Binds Replication codecs, runtime rule projections, traceable samples, strict nested boundaries, and D1-D5 mutations. | Auditing Replication persistence compatibility. |
| `src/replication/source_a_census.rs` | Exposes Replication's four exact source-(a) kind, digest, disposition, and provenance rows to the union census. | Auditing Replication source-(a) completeness without loading codec tests. |
