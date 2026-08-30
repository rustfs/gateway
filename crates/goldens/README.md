# rustfs-gateway-goldens

Fail-closed compatibility evidence for persistence migrations away from the pinned s3s codec.
The crate keeps old and new observations independent while checking compatible reads,
byte-identical writes, rollback reads, parser permissiveness, and runtime behavior.
