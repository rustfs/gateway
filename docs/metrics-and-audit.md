# Metrics and audit

What RustFS records about each S3 request, where each fact comes from once the gateway answers the
request, and what the gateway's two report hooks — `Observer` and `AuthzAuditSink` — carry of it.
RustFS is the host this is written for; the hooks are the same for any host.

[docs/middleware.md](middleware.md) covers when to watch with an `Observer` rather than rewrite with
a filter, and [docs/observability.md](observability.md) the gateway's own `tracing` events;
`crates/gateway/tests/host_reporting.rs` is a recording implementation of both hooks, shaped like
RustFS's counter and audit entry.

## What RustFS records today

Read at rustfs/rustfs `3268c42e00`.

| Record | Written by | Its inputs |
| --- | --- | --- |
| `rustfs_s3_http_requests_total{method, op, outcome}` | the request-context layer (`rustfs/src/server/layer.rs:280-363`) | method (nine known ones and `OTHER`) and status from the HTTP exchange; `op` recorded by handler code into a task-local the layer scopes over the request (`crates/io-metrics/src/s3_http_metrics.rs:40-113`, `:150-156`), `unknown` when no handler recorded one |
| `rustfs_s3_operations_total{op}` | handler code, through `record_s3_op` (`crates/io-metrics/src/s3_api_metrics.rs:45-51`) | the handler's own operation name, `s3:GetObject` |
| `rustfs_http_server_*` | the in-flight and trace layers (`rustfs/src/server/http.rs:2120-2175`) | method, status, `Content-Length`, response frames, latency to the head |
| the audit entry | `OperationHelper`, in handler code (`rustfs/src/storage/helper.rs:86-440`) | bucket and object from the handler's request info, falling back to the raw path (`:127-151`); the handler's result (status, error message); the request context's identifier; the request's headers (in `requestQuery`, `:188`), path and host; the response's headers; and as `accessKey` the server's own credential, not the caller's (`:349-351`) |
| the bucket event notification | the same helper, on success (`rustfs/src/storage/helper.rs:425-437`) | as the audit entry, plus the verified access key as `principalId` |
| `http_request_completed` | the request-logging layer, `log_response` (`rustfs/src/server/layer.rs:481-539`) | the request context, peer, method, redacted target, status, duration |

## Where each fact comes from under the gateway

The layers around the service and the handlers inside it are RustFS's either way, so most facts do
not move: the gateway sits where the legacy stack sits, between the two.

| Fact | RustFS today | Under the gateway | In the hooks |
| --- | --- | --- | --- |
| Request identifier | the request-context layer (`rustfs/src/storage/request_context.rs:121-142`), which also rewrites `x-amz-request-id` on every S3 answer (`rustfs/src/server/layer.rs:364-368`) | the same layer. The hooks and the gateway's answer carry the gateway's identifier; until the host hands its own over (rustfs/gateway#1150), RustFS's rewrite leaves its records and the caller's header naming one request and the hooks and the error document another | `RequestEvent::request_id`, `AuthzAuditEvent::request_id` |
| Method | the layer | the layer; also `RequestContextView::method` in handler code | `RequestEvent::method()`, for a counter kept in the observer |
| Status, outcome | the layer, from the final response | the same | `RequestEvent::status` |
| Operation | handler code, into the layer's task-local | the same, as long as the handler records it on the request's task — the gateway runs a handler on the request's task, and only the work a handler hands back to finish after a committed head runs on a task of its own | `RequestEvent::operation`: the gateway's operation name (`GetObject`, RustFS's `s3:GetObject`), `None` when routing chose none |
| Error code | not recorded | — | `RequestEvent::error` |
| Error message (audit `error`) | handler code, from its own error | handler code, from its own answer | none: a refusal of the gateway's has only the gateway's sentence |
| Access key (notification `principalId`, denial log `account`) | the legacy stack's verified credentials | the handler context's principal (`RequestContextView`) | `RequestEvent::identity` (`None` unless authentication succeeded), `AuthzAuditEvent::identity` |
| The caller behind an audit entry | not recorded: the entry's `accessKey` is the server's own credential | unchanged | `RequestEvent::identity`, for a host that wants the caller |
| Bucket, object, version | the handler's request info (the typed input), in handler code | the typed input, in handler code | `AuthzAuditEvent::bucket` and `key`, for every request that reached authorization |
| Source address, user agent, host, path, request headers | the layers, and the legacy request's headers in handler code | the layers, and the handler context's head (`RequestContextView::headers`, `raw_path`, `host`) | none, by design: a header value in a log sink is how a session token leaks |
| Response headers (audit `responseHeader`) | the legacy response, in handler code | the handler's own answer | none |
| Bytes in and out, time to first byte, duration, cancellation | the layers | the layers | none: the observer is called once the head is decided, before any body byte — a committed answer's once its detached work ends, after its head and any keep-alive bytes went out — and a request whose future is dropped before an answer is not observed |

## What only the hooks see

- The requests the gateway refuses before any handler runs — a signature, a limiter, a head or
  input it cannot read. RustFS's layers count them with `op="unknown"`, as they count the requests
  the legacy stack refused; `RequestEvent::operation` names the operation routing chose, when it
  chose one, and `error` the code the caller was answered with. A host that wants those counted
  under their operation keeps its counter in the observer instead of its layer — not in both,
  which would count every request twice.
- Every authorization decision, `Indeterminate` and the `s3:ListBucket` visibility check included
  (`AuthzAuditEvent`). A host that decides authorization in its handlers rather than in an
  `Authorizer` sees only `Allow` here, and keeps writing its own denial records.

## Wiring

Both hooks are synchronous and called on the request path — a committed answer's observer event
on the task its detached work runs on; an implementation copies the fields it keeps and hands them
to its own task. Neither may panic — a panic is contained, the event is lost, and the answer goes
out unchanged.

```rust
use std::sync::Arc;

use rustfs_gateway::{AuthzAuditEvent, AuthzAuditSink, Observer, RequestEvent, ServiceBuilder};

struct Recorder; // a channel sender, in a real host

impl Observer for Recorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        let _ = (event.request_id, event.method(), event.operation, event.status, event.error);
    }
}

impl AuthzAuditSink for Recorder {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        let _ = (event.request_id, event.bucket, event.key, event.action, event.decision);
    }
}

let recorder = Arc::new(Recorder);
let _builder = ServiceBuilder::new().observer(Arc::clone(&recorder)).authz_audit(recorder);
```

The request identifier is the join key: the observer's event and the audit sink's events always
carry the same value, and the caller's `x-amz-request-id` carries it too unless something after the
gateway rewrites that header — RustFS's request-context layer does, until it hands its identifier to
the gateway (rustfs/gateway#1150).
