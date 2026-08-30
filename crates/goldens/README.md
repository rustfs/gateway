# rustfs-gateway-goldens

Fail-closed compatibility evidence for persistence migrations away from the pinned s3s codec.
The crate keeps old and new observations independent while checking compatible reads,
byte-identical writes, rollback reads, parser permissiveness, and runtime behavior.

The current executable pilot covers Versioning and Object Lock. Object Lock includes ten
SHA-pinned, old-readable synthetic oracle variants for structure, order, namespace, unknown-field,
and the Object Lock enabled-decision seam. Unknown children nested inside `Rule` or `DefaultRetention` are pinned
old/new rejection cases, so they are not counted as D1-D5 samples. None of these cases is represented
as captured client or cluster corpus; those sources remain a separate P9-01 deliverable and must not
be inferred from the sample count.
