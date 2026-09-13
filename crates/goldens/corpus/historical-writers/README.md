# Historical writer captures

These raw XML files came from disposable four-drive writers using synthetic buckets and generated credentials. The writer processes were stopped before the native RustFS `inspect bucket-meta --raw` exporter read their metadata. The manifest records the measured source-file digests before and after export; every pair is identical.

| Writer version | Captures | Nonempty exported fields |
| --- | ---: | ---: |
| RustFS 1.0.0-alpha.64 | 1 | 7 |
| RustFS 1.0.0-alpha.94 | 1 | 13 |
| RustFS v1.0.0-beta.1 | 1 | 12 |
| RustFS 1.0.0-beta.12 | 1 | 12 |
| MinIO RELEASE.2025-04-22T22-12-26Z | 2 | 11 |
| MinIO RELEASE.2025-09-07T16-13-09Z | 1 | 7 |

The seven captures contain 91 configuration observations: 62 nonempty fields and 29 empty fields. The nonempty observations deduplicate to 28 kind/digest pairs. The manifest keeps every writer alias, including bytes already registered elsewhere in the corpus. Source rows count unique digests per writer; capture totals count every observed field. Empty fields retain their observed HTTP status and error code and do not become passing configuration samples.

All four RustFS versions persisted Notification XML despite returning HTTP 400 or 500. Those bytes are compatibility inputs; the capture is not described as a successful request. MinIO's initial SDK replication request failed; the later `mc replicate add` operation succeeded after both buckets had versioning enabled. Both results remain in the manifest. The first April MinIO capture, before those prerequisites were added, is retained too.

MinIO captures used an ephemeral development KMS key and a loopback webhook sink after the initial run. Their offline export paths use a directory symlink from `.rustfs.sys` to the original `.minio.sys`; the metadata bytes were not rewritten. RustFS's official `1.0.0-rc.6` exporter is pinned by its binary digest in the manifest. Its raw-export implementation reads the metadata fields directly: <https://github.com/rustfs/rustfs/blob/5cd58319ed6148ed7f09f2a4d0b4e46e429f043a/rustfs/src/inspect.rs>.

Writer binary versions were observed independently of container build labels. Both identities are retained when they differ. Release artifacts for the two direct binary captures are:

- <https://github.com/minio/minio/releases/download/RELEASE.2025-04-22T22-12-26Z/minio.linux-arm64.RELEASE.2025-04-22T22-12-26Z>
- <https://github.com/rustfs/rustfs/releases/download/1.0.0-beta.12/rustfs-linux-aarch64-musl-v1.0.0-beta.12.zip>

The manifest pins the exporter, capture script, runtime-version output, source files, and exported metadata blobs. Fixture filenames are the SHA-256 of the unmodified XML bytes. `historical_writer::append` evaluates every nonempty observation with the existing old/new D1-D5 codecs, then admits only previously unseen kind/digest pairs to the shared corpus.
