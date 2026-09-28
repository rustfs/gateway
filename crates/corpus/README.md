# rustfs-gateway-corpus

The store behind `corpus/`: a versioned schema for recorded S3 requests, a **fail-closed**
redaction gate that refuses anything it cannot prove clean, value-free deduplication, and
per-operation bucketing with a retained cap.

It does not record. Recording is a feature-gated tower layer in the RustFS main repository and
never compiles into a production build; this crate only ever sees the JSONL that layer wrote.

The gate's polarity is the point: `ingest` **refuses** an entry that still carries credential
material rather than quietly repairing it, because a repair nobody sees is how a leak becomes
invisible. Repair is a separate, explicit `--sanitize` pass that records every field it touched.

The sanitizer never rewrites payload bytes, with one structural exception: in a request whose
head declares aws-chunked framing, the `chunk-signature` extension and the
`x-amz-trailer-signature` line sit at places the wire format fixes, so their values are replaced
with `__REDACTED__` and recorded as `chunk-signature` / `x-amz-trailer-signature` in `redacted`.
No data byte and no chunk-size line changes, which is what keeps a recorded signed-chunk body a
real example of that framing. The same text in an unframed body is user data and stays a refusal.

Likewise, a declared `multipart/form-data` upload form (`PostObject`) has its credential fields
— `x-amz-signature`, `x-amz-credential`, `signature`, `awsaccesskeyid`, `x-amz-security-token` —
rewritten and recorded as `form:<field>`. Those fields are invisible to the text rules (no
`Signature=`, and a SigV2 signature is far shorter than a secret key), so they have a rule of
their own in both scanners.
