# Ring 1 server-runtime scope

`rustfs-gateway-server` owns a mechanism only when it is useful to an arbitrary HTTP
`tower::Service` and needs no RustFS state. The crate therefore owns socket2 listener tuning,
TLS accept and atomic config replacement, Hyper h1/h2 tuning, connection admission,
connection-level progress deadlines, explicit graceful shutdown, generic prefix dispatch, and
general tower layer attachment points.

The following remain deployment-specific and were deliberately not moved from RustFS:

| Item | Why it remains outside ring 1 |
| --- | --- |
| `ReadinessGateLayer` | Reads the RustFS readiness state machine |
| `Keystone` | Applies RustFS deployment authentication policy |
| `TrustedProxy` policy | Trust boundaries are deployment-owned |
| tonic routes for `NodeService`, `HealControl`, `TierMutation` | Internode RPC is a RustFS protocol choice |
| `/rustfs/rpc/` | A concrete prefix belongs in the ring-2 RPC adapter; ring 1 accepts caller prefixes |
| Console static assets | Product UI, not HTTP runtime machinery |
| Admin router | RustFS business API |
| Certificate file watcher | Platform and retry policy belong to the deployment |
| `BodylessStatusFixLayer` | s3s compatibility patch; the replacement renderer is correct by construction |
| `HeadRequestBodyFixLayer` | s3s compatibility patch; response invariants own HEAD behaviour |
| `DoubleSlashListBucketsCompatLayer` | s3s compatibility patch; routing owns the wire rule |
| `VirtualHostStyleHintLayer` | s3s compatibility patch; the host resolver owns addressing |
| `EmptyBodyContentLengthCompatLayer` | s3s compatibility patch; response encoding owns content length |
| `S3ErrorMessageCompatLayer` | s3s compatibility patch; one error renderer owns the document |
| `ObjectAttributesEtagFixLayer` | s3s compatibility patch; the operation codec owns the field |
| `StsQueryApiCompatLayer` | STS is a ring-2 operation family |
| `ConditionalCorsLayer` | CORS is already a typed facade extension |

Host normalization remains in the signing/acceptance path. Request-body read intervals and handler
progress deadlines remain in the protocol core. Duplicating any of those in this transport crate
would create two authorities for one decision.
