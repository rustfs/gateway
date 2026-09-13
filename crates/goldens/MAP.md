# MAP — rustfs-gateway-goldens

Agent entry point. File → responsibility → when you need to open it.

## Files

| File | Responsibility | Read it when |
| --- | --- | --- |
| `src/lib.rs` | Runs fail-closed persistence compatibility assertions against independent old and new codecs. | Adding a configuration family or changing a D1-D5 assertion. |
| `src/operation_diff.rs` | Test-only: binds each seam revision (`s3s_9c4690d8`, `s3s_f3e17541`) to one compilation of the harness and every proof under `operation_diff/`, with `SEAM_REVISION` for the rare revision-dependent answer. | Running a proof under another s3s revision, or a proof that differs by revision. |
| `src/operation_diff/harness.rs` | Test-only harness: one raw request through the real gateway route and codec and through the bound revision's s3s service, with every body read counted. | Adding an operation to the decode/encode diff or changing how either stack is driven. |
| `src/operation_diff/put_object.rs` | PutObject decode diff: member-by-member zero diff, body read once and never before the handler, one-member mutations, and the census. | A PutObject request decodes differently on the two stacks, or the conversion changes. |
| `src/operation_diff/context.rs` | Test-only context harness: one raw (optionally SigV4-signed, optionally virtual-hosted) request served by a real assembled gateway whose handler builds the s3s context from `Req::context()` alone (ADR-0022), and by the pinned s3s service with auth and host configured; compares every `S3Request` context member. | Changing how the gateway-side context is assembled or which context member is compared. |
| `src/operation_diff/context/put_object.rs` | PutObject context diff: method, URI, headers, extensions, credentials, region, service and trailers equal, one-member mutations, conversion refusals, and each known context divergence named. | A PutObject request context differs between the stacks, or the context conversion changes. |
| `src/operation_diff/context/answers.rs` | Test-only: each stack's status and body for one signed request, refusals included, for the rd-loc pins. | A rd-loc pin needs another part of the answer. |
| `src/operation_diff/context/get_bucket_location.rs` | GetBucketLocation context diff (rustfs/backlog#1752): the same context equality for a bodiless bucket read, path-style and virtual-hosted, the seam input equal to what s3s decodes, the output conversion, and its census. | Auditing the M1 compile/context proof for GetBucketLocation. |
| `src/operation_diff/put_object/encode.rs` | PutObject encode diff: same status, header lines and body from both stacks, and every uncarriable output refused by name. | A PutObject answer is written differently, or the output conversion changes. |
| `src/migration_inventory.rs` | Re-proves decided refusals (rustfs/gateway#469 persisted DOCTYPE) across every family, form and pinned revision, and that no writer sample carries the refused syntax. | Auditing a decided persisted-read refusal or its operator remediation. |
| `src/migration_inventory/tests.rs` | Proves every way a decided refusal can stop holding is refused by name. | Verifying the inventory fails closed. |
| `src/operation_diff/put_object/divergences.rs` | PutObject decode: each known divergence between the stacks as a named test carrying its ruling id. | A PutObject request decodes differently on the two stacks, or a ruling changes. |
| `src/migration_inventory/request_divergences.rs` | The ruling register for the 14 request divergences the rustfs/backlog#1762 differential pins: AWS, s3s and gateway behaviour, client impact, ruling and owner issue. | Deciding or auditing how the RustFS migration treats a request the two stacks answer differently. |
| `src/migration_inventory/request_divergences/tests.rs` | Binds every register entry to the pinned test carrying its id and back, and refuses every malformed entry by name. | Adding a pinned divergence test or a ruling. |
| `src/oracle_admission.rs` | Runs D1-D5 and re-reads every rejected sample under each pinned s3s revision, matching moved refusal boundaries to registered findings in both directions. | Auditing rollback/candidate admission or registering or resolving an oracle finding. |
| `src/oracle_admission/tests.rs` | Proves real per-revision observation and every admission rejection with synthetic registries and relabelled observations. | Verifying oracle admission fails closed. |
| `src/acceptance_census.rs` | Binds the exact 39 P9-01 IDs to runtime or pinned external evidence without counting blockers as passing. | Auditing final case closure, blocker disposition, or census mutations. |
| `src/corpus.rs` | Derives coverage from concrete traceable accepted/rejected samples without claiming aggregate completeness. | Wiring family-owned sample collections or changing corpus validation. |
| `src/historical_writer.rs` | Validates six historical writers and runs every nonempty captured field through D1-D5 with digest deduplication. | Auditing source-(d′) admission or a persisted field from a failed request. |
| `src/historical_writer/data.rs` | Binds digest-named raw exports and exact per-writer witness sets. | Auditing historical aliases or changing a capture registration. |
| `src/historical_writer/tests.rs` | Mutates capture completeness, stopped-source receipts, and byte bindings. | Verifying the historical matrix fails closed. |
| `corpus/historical-writers/manifest.json` | Records seven actual capture receipts, including empty fields and source digest measurements. | Looking up writer identity, request outcomes, or a raw export digest. |
| `src/provenance.rs` | Reports present and absent approved sources, validates writer witnesses, refuses a partial (d′) writer matrix, and separately requires all four sources for closure. | Registering a collected source, auditing writer provenance, or asking why closure is still held. |
| `src/corpus/backup_zip.rs` | Proves old/new backup archives preserve every accepted persisted XML byte and remain readable in both migration directions. | Auditing backup import/export rollback evidence or its fail-closed archive checks. |
| `src/source_a_boundary.rs` | Binds the four physical CORS and Lifecycle rule-cap fixtures to exact source-(a) paths, case IDs, and SHA-256 digests. | Auditing physical fixture census or rule-count boundary migration evidence. |
| `src/source_a_census.rs` | Fails closed unless all 38 audited source-(a) references map to the exact 30 kind/digest/disposition corpus registrations and sample/alias roles. | Auditing aggregate source-(a) completeness or adding a physical RustFS fixture binding. |
| `src/source_a_lifecycle.rs` | Registers one unique RustFS Lifecycle metadata-test literal and two exact marshal provenance aliases. | Auditing source-(a) Lifecycle byte identity or alias deduplication. |
| `src/source_a_new_writer.rs` | Binds selected RustFS CORS and Lifecycle `NEW_WRITER_CONFIGS` bytes to exact source references and SHA-256 digests. | Auditing source-(a) new-writer rollback fixtures or their census. |
| `src/source_b_mc.rs` | Registers official-mc CORS and Lifecycle raw exports plus a deduplicated Versioning provenance alias. | Auditing the live mc client matrix, raw metadata digests, or alias census. |
| `src/source_b_rclone.rs` | Binds rclone's only supported bucket-configuration capture as a deduplicated Versioning provenance alias. | Auditing rclone client capability evidence, raw metadata identity, or alias census. |
| `src/bin/corpus-report.rs` | Renders the corpus, source, and acceptance census; `--require-closure` enforces final migration acceptance. | Running or changing the persistence corpus CLI. |
| `src/bin/four-way.rs` | Executes all persisted XML samples through D1-D5 with a fail-closed process status. | Running or changing the full persistence rollback gate. |
| `tests/cli.rs` | Observes real report and strict-closure process output and status. | Changing CLI census visibility or migration gate behavior. |
| `src/accelerate_payment.rs` | Binds Accelerate and Request Payment production/oracle codecs, decision projections, traceable samples, and mutations. | Auditing Accelerate or Request Payment persistence compatibility. |
| `src/versioning.rs` | Binds Versioning codecs, concrete accepted/refused corpus rows, runtime behavior, and D1-D5 mutations. | Auditing Versioning persistence compatibility or its corpus coverage. |
| `src/object_lock.rs` | Binds Object Lock production/oracle codecs, enabled-decision projection, traceable samples, and mutations. | Auditing Object Lock persistence compatibility. |
| `src/lifecycle.rs` | Binds Lifecycle codecs, D1 structural evidence, D5 enabled decisions, traceable samples, parser boundaries, and mutations. | Auditing Lifecycle persistence compatibility. |
| `src/lifecycle/source_b.rs` | Registers the byte-exact Lifecycle sample captured through the live source-(b) client path. | Auditing the boto3-to-RustFS persistence provenance for Lifecycle. |
| `src/notification.rs` | Binds Notification codecs, full routing decisions, traceable samples, parser boundaries, and D1-D5 mutations. | Auditing Notification persistence compatibility. |
| `src/notification/corpus_cases/source_a.rs` | Pins RustFS repository Notification fixture bytes, aliases, old-oracle classification, and provenance. | Registering or auditing Notification source-(a) census rows. |
| `src/bucket_encryption.rs` | Binds Bucket Encryption codecs, algorithm/KMS/bucket-key/blocked-type behavior and traceable samples, including the revision-scoped `BlockedEncryptionTypes` samples (D1-D5 under rollback/candidate, widenings under the baseline). | Auditing default-encryption persistence compatibility or the per-revision rule (rustfs/gateway#740). |
| `src/bucket_encryption/tests.rs` | Proves every Bucket Encryption sample, the per-revision widening rule, and that each direction goes red under a broken codec. | Verifying Bucket Encryption evidence fails closed. |
| `src/public_access_block.rs` | Binds Public Access Block codecs, four-switch behavior, traceable samples, and mutations. | Auditing public-access persistence compatibility. |
| `src/cors.rs` | Binds CORS production/oracle codecs, full runtime projection, samples, parser boundaries, and mutations. | Auditing CORS persistence compatibility. |
| `src/tagging.rs` | Binds Tagging production/oracle codecs, complete tag projection, samples, parser boundaries, and mutations. | Auditing Tagging persistence compatibility. |
| `src/logging.rs` | Binds Bucket Logging codecs, delivery behavior, traceable samples, and mutations. | Auditing access-log configuration persistence. |
| `src/website.rs` | Binds Website codecs, routing behavior, traceable samples, and mutations. | Auditing static-website configuration persistence. |
| `src/replication.rs` | Binds Replication codecs, runtime rule projections, traceable samples, strict nested boundaries, and D1-D5 mutations. | Auditing Replication persistence compatibility. |
| `src/replication/source_a_census.rs` | Exposes Replication's four exact source-(a) kind, digest, disposition, and provenance rows to the union census. | Auditing Replication source-(a) completeness without loading codec tests. |
