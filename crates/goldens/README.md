# rustfs-gateway-goldens

Fail-closed compatibility evidence for persistence migrations away from the pinned s3s codec.
The crate keeps old and new observations independent while checking compatible reads,
byte-identical writes, rollback reads, parser permissiveness, and runtime behavior.

The current executable evidence covers Versioning, Object Lock, Bucket Encryption, and Public
Access Block. Each security-configuration family includes ten SHA-pinned, old-readable synthetic
oracle variants plus explicit duplicate, required-field, unknown-field, boolean-lexeme, serializer
order, and D1-D5 mutation cases. D5 projects only real runtime decisions: Object Lock enablement,
SSE algorithm/KMS key/bucket key, and the four public-access switches. None of these cases is
represented as captured client or cluster corpus; those sources remain a separate P9-01 deliverable
and must not be inferred from the sample count.
