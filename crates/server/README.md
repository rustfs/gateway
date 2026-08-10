# rustfs-gateway-server

**RING 1 — general purpose, zero rustfs dependencies.**

This crate owns the reusable socket, TLS, Hyper connection, admission, timeout, path dispatch and
graceful-shutdown runtime. It accepts any compatible cloneable `tower::Service`; it contains no
storage, IAM, cluster, console, admin or concrete RPC-route policy.

Cleartext is fail-closed: `ServerConfig::default()` requires a `TlsHandle`. A deployment must set
`plaintext = true` explicitly to listen without TLS. Failed TLS reloads leave the previous config
active for future connections, while established TLS sessions retain the config used at handshake.
