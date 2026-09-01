# rustfs-gateway-dialect-minio

Clean-room, explicitly selected protocol extensions for MinIO-compatible wire bytes.

This crate owns concrete extension registrations. It does not contain MinIO server code or make
the extensions part of the default S3 protocol surface.
