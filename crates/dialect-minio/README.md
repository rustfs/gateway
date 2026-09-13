# rustfs-gateway-dialect-minio

Clean-room, explicitly selected protocol extensions for MinIO-compatible wire bytes.

This crate owns concrete extension registrations. It does not contain MinIO server code or make
the extensions part of the default S3 protocol surface.

- `MinioLifecycleDialect`: the lifecycle `DelMarkerExpiration` field.
- `replication_dialect()`: the replica write `minio:PutObjectReplica`, a `PUT` carrying
  `?versionId=` that stores the object under that id. Installing it is an explicit choice
  (`ServiceBuilder::dialect`, plus a handler registered for `PutObjectReplica`), and it is
  authorised as `s3:ReplicateObject` and `s3:PutObject` on the key. Without it the query is
  ignored, as on AWS.
