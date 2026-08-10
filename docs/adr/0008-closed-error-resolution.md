# ADR-0008: Closed error resolution across the types, core and facade boundary

- Status: Accepted
- Date: 2026-08-11
- Trigger: axioms A2 and A3 (invalid response combinations must be unrepresentable, and resolution order is fixed by types)
- Supersedes / Superseded by: none

## Context

`ErrorCode` owns the context-free code-to-status table. `ErrorContext` currently has six public
fields plus `Default`, while `mask_for_authorization` and `status_of` are two separately callable
public functions. The facade then constructs `S3Error`, may replace its status with `with_status`,
attaches details and headers, and renders the response. Each individual API is useful, but their
composition can represent results S3 never sends: a `204` carrying `NoSuchKey` XML, a `304` with a
framed body, a hidden missing key whose status was selected before authorization masking, or an
authorization-region error with no `Region` detail.

rustfs/backlog#1706 names eleven observable error cases. Four are context-free table properties;
the others need operation, authorization, response-method or header/body context. They are one
contract because clients observe one response, not independently selected code, status, headers
and body:

| Case | Observable result |
|---|---|
| `c-err-n001` | An unknown custom code resolves to `400`, never the fallback `500` |
| `c-err-n002` | A missing key is `403 AccessDenied` without ListBucket and `404 NoSuchKey` with it |
| `c-err-n003` | DeleteObject on a missing key is a successful empty `204`; a missing bucket remains `404 NoSuchBucket` |
| `c-err-n004` | A versioned read of a delete marker is `405 MethodNotAllowed` |
| `c-err-n005` | `MissingContentLength` is `411`, not `400` |
| `c-err-n006` | `EntityTooLarge` is `400`, not `413` |
| `c-err-n007` | Every HEAD refusal preserves its status and headers but has no body or body framing |
| `c-err-n008` | Not Modified is `304`, carries the ETag, and has neither body nor `Content-Length` |
| `c-err-n009` | A signing-region mismatch is `400 AuthorizationHeaderMalformed` with one bounded `Region` detail |
| `c-err-n010` | A refused preflight is `403 AccessForbidden` with the canonical, static CORSResponse message pinned by `c-cors-0034` |
| `c-err-n011` | Only explicitly declared server errors resolve to `5xx`; no table miss does |

The `204` case is the proof that this cannot remain only an error-code mapping: there is no honest
error code to put in a successful response. The HEAD and `304` cases are the proof that a status is
not enough: body and framing policy are part of the same decision. The region and CORS cases are
the proof that arbitrary strings are not an acceptable escape hatch: one value comes from bounded
configuration and the other is a protocol constant.

## Decision

The types crate keeps `ErrorCode` and the context-free code-to-status table. Its public
`ErrorContext`, contextual `status_of` signature and `mask_for_authorization` function are removed;
the table becomes a pure `ErrorCode` lookup and keeps the existing unknown-code `400` fallback.
Operation and authorization facts do not belong in the scalar crate.

Core replaces them with an opaque public `ErrorContext` whose representation and fields are
private. It has no `Default`, no general builder, no public field setters and no public
destructuring API. This is the complete public construction and resolution surface; helper
transitions remain private:

```rust,ignore
pub enum MissingObject {
    Key,
    Version,
}

pub enum ResourceVisibility {
    Hidden,
    Visible,
}

pub enum ResponseKind {
    Head,
    Other,
}

pub enum InvalidErrorContext {
    ContextRequired,
    InvalidCode,
    InvalidVersionId,
    InvalidMessage,
    InvalidDetail,
    ReservedExtra,
}

pub enum BodyPolicy {
    None,
    ErrorDocument,
}

impl ErrorContext {
    pub fn ordinary(error: HandlerError) -> Result<Self, InvalidErrorContext>;
    pub fn codec(error: CodecError) -> Result<Self, InvalidErrorContext>;
    pub fn missing_object(kind: MissingObject, visibility: ResourceVisibility) -> Self;
    pub fn delete_missing_key() -> Self;
    pub fn missing_bucket() -> Self;
    pub fn foreign_bucket() -> Self;
    pub fn permanent_redirect(region: RegionLabel) -> Self;
    pub fn temporary_redirect(region: RegionLabel, target: RedirectTarget) -> Self;
    pub fn owned_bucket_recreation(region: RegionLabel) -> Self;
    pub fn versioned_delete_marker(version_id: &str) -> Result<Self, InvalidErrorContext>;
    pub fn authorization_region_mismatch(region: RegionLabel) -> Self;
    pub fn not_modified(etag: ETag) -> Self;
    pub fn cors_forbidden() -> Self;
}

pub fn resolve(context: ErrorContext, response: ResponseKind) -> ErrorResolution;

impl ErrorResolution {
    pub const fn status(&self) -> StatusCode;
    pub fn code(&self) -> Option<&ErrorCode>;
    pub const fn body_policy(&self) -> BodyPolicy;
    pub fn message(&self) -> Option<&str>;
    pub fn headers(&self) -> &[ErrorHeader];
    pub fn details(&self) -> &[ErrorDetail];
    pub fn etag(&self) -> Option<&ETag>;
    pub fn resource(&self) -> Option<&str>;
}
```

`missing_object` selects `NoSuchKey` or `NoSuchVersion`. Both become `AccessDenied` when visibility
is `Hidden`; both retain their precise `404` code when it is `Visible`. `delete_missing_key` means
the bucket has already been found and therefore cannot carry `NoSuchBucket`. The
`versioned_delete_marker` constructor refuses an empty or over-1024-byte version id; the id proves
that the lookup was version-specific but is not retained or rendered. Constructors for redirects,
authorization-region errors and Not Modified require the existing bounded `RegionLabel`,
`RedirectTarget` and `ETag` values. Special constructors choose their code, status, message,
headers and details internally; none accepts a replacement code or message.

`ordinary` is the only constructor that accepts a `HandlerError`. It permits known context-free
codes and unknown custom codes; an unknown custom code still resolves to `400`. It rejects
`NoSuchKey`, `NoSuchVersion`, `NoSuchBucket`, `PermanentRedirect`, `TemporaryRedirect`,
`NotModified`, `AuthorizationHeaderMalformed`, `MethodNotAllowed`, `BucketAlreadyOwnedByYou` and
`AccessForbidden` with `InvalidErrorContext::ContextRequired`. Those codes can enter resolution
only through the named constructor that supplies their missing fact. This deny set is exhaustive
for the contextual outcomes accepted by this ADR and is fixed by a deterministic guard and one
mutation per member.

For an unknown `ErrorCode::custom`, `ordinary` applies the same XML 1.0 text predicate used below,
then requires 1..=128 ASCII bytes matching `[A-Za-z][A-Za-z0-9]{0,127}`. The accepted control for
`c-err-n001` is `VendorSpecific`, which remains an unknown code and resolves to `400`. An empty,
over-128-byte, punctuated or control-character-bearing custom code returns
`InvalidErrorContext::InvalidCode`; it is never copied into an `InternalError`.

An ordinary message and every dynamic XML detail (`Key`, `BucketName`, `Condition` and
`RangeRequested`) must be valid XML 1.0 text. Valid text is exactly tab, line feed, carriage return,
`U+0020..U+D7FF`, `U+E000..U+FFFD` or `U+10000..U+10FFFF`; every other control character is rejected
before compatibility or rendering. The message and `Key` are each at most 1,024 UTF-8 bytes,
`BucketName` is at most 63 bytes, `Condition` is one of `If-Match`, `If-None-Match`,
`If-Modified-Since` or `If-Unmodified-Since`, and `RangeRequested` is at most the existing 16 KiB
request-header limit. `ActualObjectSize` is numeric and `RegionLabel` already fixes its own byte
set and 64-byte limit. Validation never truncates. It returns `InvalidErrorContext`; the service
boundary converts an unhandled validation failure to a static `InternalError` without echoing the
refused text. Special-case messages, including the CORS message, are `&'static str` constants.

The generic `HandlerError::with_header` and `with_detail` methods may remain input builders, but
they confer no authority to render an extra. `ordinary` validates this closed compatibility matrix
after validating text and before constructing `ErrorContext`; an absent row is forbidden:

| Extra set | Permitted public code and consistency rule |
|---|---|
| `UnsatisfiedRange`, `RangeRequested`, `ActualObjectSize` | only `InvalidRange`; all three occur together exactly once, its status is `416`, and the header's `complete_length` equals `ActualObjectSize` |
| `Condition` | only `PreconditionFailed`; exactly one of the four static condition names above |
| `RetryAfter` | only `SlowDown` or `ServiceUnavailable` |
| `Key` | only `NoSuchKey`, `NoSuchVersion` or `InvalidObjectState` |
| `BucketName` | only `NoSuchBucket`, `PermanentRedirect` or `BucketAlreadyOwnedByYou` |
| `AuthorizationHeaderMalformed` | requires exactly one `Region`; forbids `BucketRegion`, `RedirectLocation` and `BucketName` |
| `PermanentRedirect` | requires one `Region` and one `BucketRegion` carrying the same `RegionLabel`; permits one validated `BucketName`; forbids `RedirectLocation` |
| `TemporaryRedirect` | requires one `Region`, one matching `BucketRegion` and one `RedirectLocation`; forbids `BucketName` |

Contextual rows are populated only by their named constructor because `ordinary` rejects their
codes. Thus `AccessDenied` with a range triple, `InternalError` with `RetryAfter`, a mismatched
range length, or `PreconditionFailed` with `BucketName` returns `InvalidErrorContext` and no
resolution. Tests mutate each row, the range equality check, every byte bound, and the shared XML
predicate; injecting `U+0001` into each dynamic detail is a separate red case. The three regional
rows each have missing-required, forbidden-extra and swapped-row mutations, plus a mutation that
makes the body and header region values disagree.

`ResponseKind::Head` is orthogonal and monotonic: it may only remove a body and its framing, never
change a code or status. Core owns `ErrorResolution`; it is opaque and exposes read-only accessors
for the status, optional public error code, body policy, optional message, ETag, bucket-region
value, redirect location and Region document detail. Its code is `None` for the successful `204`
outcome. Its header/detail accessors return the existing closed `ErrorHeader` and `ErrorDetail`
values rather than arbitrary names and strings.

Resolution runs in one fixed order:

1. the constructor identifies the semantic situation and whether it is success or refusal;
2. resource-visibility masking chooses the public code, so a hidden key is already
   `AccessDenied` before any status or document is selected;
3. the context-free table selects ordinary statuses, with its existing `400` fallback, while the
   closed special cases select `204`, `301`, `304`, `307`, `405` or the us-east-1 `200`;
4. the special case supplies its required static message and typed headers/details;
5. `ResponseKind::Head`, successful `204`, and `304` force `BodyPolicy::None` and forbid
   `Content-Length` and `Content-Type`; all other refusals use `BodyPolicy::ErrorDocument`.

The facade consumes one `ErrorResolution` when it builds the response. Existing closed
`ErrorHeader` and `ErrorDetail` values carried by an authorized handler are merged by core before
the resolution becomes observable, and cannot replace a resolution-owned status, public code,
reserved header, canonical message or body policy. The public semantic constructors on `S3Error`,
including `new` and `with_status`, become private conversion details. The only public construction
bridge is `impl From<ErrorResolution> for S3Error`; it copies an already opaque, validated
resolution and exposes no fields or setters. The gateway re-exports `ErrorContext`,
`ErrorResolution` and their construction enums from core beside `S3Error`.

Every current public `From<X> for S3Error` other than that new bridge is removed. Closed wire,
chunk, pre-authentication, authentication, denial and SSE inputs use private facade conversion
functions. Each function either supplies a named `ErrorContext` and calls `resolve`, or combines a
resolved semantic shape with the typed `ConnectionIntent` that only the transport path owns.
These helpers are not traits and are not re-exported. A new public `From` implementation would be
a second construction bridge and is guard-forbidden.

The public `From<HandlerError> for S3Error` conversion is removed with those constructors. The
facade's private handler-error conversion calls `ErrorContext::ordinary`, handles its failure as
the static `InternalError` above, resolves once, and renders only that resolution.

`S3Error::about_resource` is removed rather than left as a post-resolution writer. Core's
`ErrorContext::codec` is the only current input that may produce a resource: it accepts the
`CodecError`'s compile-time model-member name only when it is valid XML 1.0 text, at most 128 bytes,
and matches `[A-Za-z][A-Za-z0-9]{0,127}`. The opaque `ErrorResolution` stores that checked resource
and exposes it read-only through `resource`; the facade copies it into its private render value.
No public `S3Error` method can add, replace or clear it. A future bucket, key or URI resource shape
requires a new typed `ErrorContext` constructor rather than reopening a string setter.

`StageFilter` no longer returns the already rendered type. Its three methods and the
`wire_filter`, `routed_filter` and `response_filter` closure bounds change from
`Result<(), S3Error>` to `Result<(), HandlerError>`. The service sends that value through
`ErrorContext::ordinary` with the actual request method and fails to the static `InternalError` if
the filter attempted a contextual code or invalid payload. `FrozenHeader` changes from
`From<FrozenHeader> for S3Error` to `From<FrozenHeader> for HandlerError`; its fixed
`InternalError` code/message remain and the header name remains absent. A filter that needs a
contextual missing-object, redirect, Not Modified or CORS outcome belongs in the typed operation,
authorization or CORS path that owns the required facts, not this generic interception seam.

`HandlerError::status` is removed: it currently resolves against `ErrorContext::default()` and
therefore exposes a context-free answer for a value that may require masking or special handling.
Callers migrate to `resolve(context, response).status()`. `HandlerError::code`, `message`, `headers`
and `details` remain inspection APIs; none can produce an HTTP response without successful
`ErrorContext` construction and resolution.

The canonical no-CORS message is `CORSResponse: no CORS rule allows this request`, matching the
current byte-exact `c-cors-0034` contract. This supersedes the older wording in the original
P1-04 backlog table without changing the code or status.

## Evidence

**Measured:** on `origin/main` at `79a9f178aa6cf23a2c9737669dbfbe60d32efe4f`, the current input
has six independently writable public facts and derives `Default`:

```text
$ sed -n '/pub struct ErrorContext {/,/^}/p' crates/types/src/scalar/error_status.rs | rg -c '^    pub '
6
```

**Measured:** the two steps whose order matters are separately public:

```text
$ rg -n '^pub fn (status_of|mask_for_authorization)' crates/types/src/scalar/error_status.rs
65:pub fn status_of(code: &ErrorCode, ctx: &ErrorContext) -> StatusCode {
94:pub fn mask_for_authorization(code: ErrorCode, ctx: &ErrorContext) -> ErrorCode {
```

**Measured:** the syntax search has eight matches: the public definition, its `impl`, and six
functional-update literals in the scalar tests. Consumers cross all three affected crates:

```text
$ git grep -n 'ErrorContext {' -- 'crates/**' ':!crates/types/generated/**' ':!generated/**' | wc -l
8
$ git grep -l 'ErrorContext' -- 'crates/**' ':!crates/types/generated/**' ':!generated/**' | cut -d/ -f2 | sort -u
core
gateway
types
```

Each match has one migration rather than disappearing behind a compatibility default:

| Current match | Migration |
|---|---|
| `error_status.rs`: public struct definition | removed from types; replaced by core's opaque `ErrorContext` |
| `error_status.rs`: `impl ErrorContext` | replaced by the named constructors and sole `resolve` entry above |
| `error_tests.rs`: `has_list_bucket_permission: true` | `missing_object(MissingObject::Key, ResourceVisibility::Visible)` |
| `error_tests.rs`: `owned_by_other_account: true` | `foreign_bucket()` |
| `error_tests.rs`: `region_mismatch: true` | `permanent_redirect(region)` |
| `error_tests.rs`: `dns_not_propagated: true` | `temporary_redirect(region, target)` |
| `error_tests.rs`: `is_head: true` | `ResponseKind::Head` at the sole resolution entry |
| `error_tests.rs`: `method: Some(Method::HEAD)` | the same `ResponseKind::Head`; method and boolean cease to be competing facts |

The existing hidden-object test already covers both `NoSuchKey` and `NoSuchVersion`. Its migration
uses `MissingObject::Key` and `MissingObject::Version` separately, and mutating either branch to
retain its `404` must fail.

**Measured:** `HandlerError` publishes a status computed through a default context, so callers can
currently ask for a contextual status without supplying the missing facts:

```text
$ rg -n '^    pub fn status\(&self\) -> StatusCode' crates/core/src/handler.rs
498:    pub fn status(&self) -> StatusCode {
```

That method is part of the BREAKING migration; it is not retained as a deprecated bypass.

**Measured:** the facade currently exposes a second status authority and its ordinary renderer
always inserts both XML content type and content length:

```text
$ rg -n 'pub fn with_status|headers.insert\((CONTENT_TYPE|CONTENT_LENGTH)' crates/gateway/src/render.rs
156:    pub fn with_status(mut self, status: StatusCode) -> Self {
388:    headers.insert(CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
390:        headers.insert(CONTENT_LENGTH, value);
```

**Measured:** the public-writer/accessor inventory was produced across every non-generated Rust
file, not only `render.rs`; the table records the disposition of every result that can construct,
return, render or re-export a refusal:

```text
$ rg -n 'S3Error' crates --glob '!generated/**' --glob '!crates/types/generated/**' --glob '*.rs'
$ rg -n '^impl From<.*> for S3Error|Result<.*S3Error|pub use .*S3Error' crates \
    --glob '!generated/**' --glob '!crates/types/generated/**' --glob '*.rs'
```

The current counts are nine `From<X> for S3Error` implementations (eight in `render.rs`, one for
`FrozenHeader` in `ext/filter.rs`), fifteen `Result<(), S3Error>` spellings in `ext/filter.rs`, one
public re-export in `lib.rs`, and three public read-only render sinks (`document`, `document_body`,
`render`).

| Current surface | Disposition |
|---|---|
| `S3Error::new`, `with_status` | private; only the resolution/typed-transport assembler calls them |
| `S3Error::closing` | private; closed `WireReject`, `ChunkReject`, authentication and denial conversions supply the typed `ConnectionIntent` |
| `S3Error::about_resource` | removed; `ErrorContext::codec` validates the resource and `ErrorResolution` owns it |
| `S3Error::{code,status,message,headers,details,connection_intent,must_close_connection}` | retained read-only; none changes renderer-consumed state |
| the eight `render.rs` implementations from `WireReject`, `ChunkReject`, `PreAuthError`, `AuthError`, `Denial`, `SseRejection`, `CodecError` and `HandlerError` | removed; private named conversion functions replace the first seven, while handler errors enter `ordinary` |
| `ext/filter.rs`: `From<FrozenHeader> for S3Error` | replaced by `From<FrozenHeader> for HandlerError`; it then crosses the same validated resolver boundary as every filter error |
| new `From<ErrorResolution> for S3Error` | the sole public construction bridge; it only wraps the opaque resolution |
| `StageFilter`'s three methods, its `Arc` forwarding impl and the three closure adapters returning `Result<(), S3Error>` | BREAKING migration to `Result<(), HandlerError>`; no filter can return an unresolved render value |
| integration-test `StageFilter` implementations and closure fixtures returning `S3Error` | migrate to `HandlerError` and continue testing the same stop/ordering behavior through resolution |
| `connection_teardown.rs` and `reject_rendering.rs` calls to the removed typed `From` implementations | drive the real service path; crate-private converter unit tests retain direct connection/render assertions |
| `middleware.rs`, `assembly_order.rs` and render unit fixtures calling `S3Error::new` or `closing` | filter fixtures return `HandlerError`; renderer fixtures begin with a valid `ErrorResolution`; connection override mutation becomes a compile-fail case |
| crate-private `gate`/`chunked` results and private `service` helpers returning `S3Error` | remain internal only; they call private typed converters or wrap `ErrorResolution`, never a public writer |
| public `document`, `document_body` and `render` functions accepting `&S3Error` | retained as read-only sinks |
| `lib.rs` re-export of `S3Error` | retained, with `ErrorContext` and `ErrorResolution` re-exported for the sole bridge |
| `HandlerError::{new,internal_error,not_implemented,unsatisfiable_range,precondition_failed,with_header,with_detail}` | retained as unvalidated handler inputs; `ordinary` validates code, text and the complete extra matrix |
| `HandlerError::{code,message,headers,details}` | retained read-only |
| `HandlerError::status` | removed; status exists only after resolution |

The renderer consumes exactly `code`, `status`, `message`, `resource`, `extras` and `connection`.
After this migration the first five come from `ErrorResolution`; `connection` comes from a closed
typed transport decision, and the internal `S3Error` has no public writer for any of the six.

**Measured:** `rg -n 'about_resource\(' crates/gateway/src crates/core/src` finds three calls, all
in `render.rs`. They migrate individually:

| Current call | Migration |
|---|---|
| the production `From<CodecError>` conversion | `ErrorContext::codec(error)` validates the static model-member resource before `resolve` |
| `the_identifiers_are_the_last_two_elements` | construct the same resource through a valid codec resolution, then retain the byte-order assertion |
| `the_identifiers_stay_last_behind_every_extra_element` | split the impossible all-extras fixture into valid matrix rows; each resolved document still proves that resource and permitted extras precede the identifiers |

Removing the last test's contradictory `InternalError` plus range, condition, bucket and region
extras is a strengthening, not a dropped ordering assertion: every legal row remains covered and
the formerly accepted illegal combination becomes a negative resolution test.

**Measured:** `c-object-0003`, `c-object-0009`, `c-bkt-0010`, `c-bkt-0027`,
`c-bkt-0030` and `c-cors-0034` already pin the `204`, `304`, owned-bucket, region and CORS wire
outcomes independently. The P1-04 audit found no one type that makes those outcomes agree with the
context-free table; the same facts are selected again in core or the facade.

**Inferred:** making `ErrorContext` opaque breaks downstream field literals immediately rather
than silently changing their meaning. That is intentional: retaining the literals while adding
more booleans would preserve source syntax and permit contradictory states. ADR-0004 already
classifies public API breaks during `0.x` as minor-version events; the implementation therefore
moves the three affected crates to their next minor versions together:
`rustfs-gateway-types` from `0.1.0+aws.2026-08-04` to `0.2.0+aws.2026-08-04`,
`rustfs-gateway-core` from `0.2.0` to `0.3.0`, and `rustfs-gateway` from `0.4.0` to `0.5.0`.
The implementation PR states `BREAKING` and includes the migration.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Add more public booleans and `Option` fields to `ErrorContext` | It permits `delete_missing_key + missing_bucket`, `not_modified + body`, and region-mismatch states with no region. Adding fields also breaks exhaustive literals, so it is neither safer nor more compatible |
| Keep `mask_for_authorization` and `status_of` as separately callable public stages | A caller can omit or reverse masking, and neither function can express `204`, the required ETag, a Region detail, or body/framing suppression |
| Give every outcome an `ErrorCode` | DeleteObject on a missing key is success. Carrying `NoSuchKey` beside `204` invites an error document on a success response and lies to every consumer of the code |
| Keep `S3Error::new` or `S3Error::with_status` as public correction hooks | They recreate a second authority after resolution and can pair any code with any status. Transport limit errors keep their typed conversion instead |
| Let `ordinary` accept contextual codes | A caller could send `NoSuchVersion` directly and bypass the same visibility mask that protects `NoSuchKey`, or emit a redirect without its required region |
| Accept arbitrary `Cow<'static, str>` messages and details because the handler is authorized | Authorization does not bound memory or response amplification, and XML validity is independent of identity. The resolver validates every dynamic value before it becomes observable |
| Preserve arbitrary `ErrorCode::custom` text because unknown codes map to `400` | The safe status does not make an unbounded or XML-invalid `<Code>` safe. A bounded identifier preserves extension codes without creating a response-amplification or document-validity bypass |
| Validate each extra's type but not its code pairing | Typed values still permit `AccessDenied` with `Content-Range` or `InternalError` with a retry promise. The final code-to-extra matrix is the contract clients observe |
| Keep `S3Error::about_resource` for codec errors | It is callable after code, status and body policy have been resolved and accepts an unbounded string. A codec fact enters before resolution through its typed constructor instead |
| Keep `StageFilter::Result<(), S3Error>` and document that filters should resolve first | `S3Error` is re-exported and the trait is public, so any retained constructor or `From` path becomes an unvalidated extension-point bypass. Returning `HandlerError` makes the service-owned resolver unavoidable |
| Keep one public `From<X> for S3Error` per closed source type | The list is already incomplete once `FrozenHeader` is counted outside `render.rs`, and every new source reopens the audit. One opaque `ErrorResolution` bridge is mechanically enumerable |
| Truncate an oversized message or detail | Truncation silently changes protocol data and can split a UTF-8 scalar or range expression. Rejection to a static internal error is deterministic and does not echo the refused value |
| Expose a public `ErrorCase` enum and let downstream match it | Every new special case becomes a downstream exhaustive-match break. An opaque context with additive named constructors keeps representation and future cases private |
| Use a general builder with setters for code, status, message, headers and body | The builder is exactly the invalid state space this ADR removes, only with method calls instead of fields |
| Put resolution in the facade | Core must make operation and authorization decisions before the facade renders them. A facade-only table would duplicate those decisions and leave core unable to construct the proof |
| Move XML rendering, trace ids and stream bodies into the types crate | That reverses the dependency boundary: protocol scalar types would acquire facade and transport responsibilities |
| Preserve the old `CORSResponse: CORS is not enabled for this bucket.` wording | The current byte-exact `c-cors-0034` case already establishes one indistinguishable preflight-refusal message. A second message would reveal which internal CORS lookup failed |

## Consequences

- The implementation is a coordinated public API change in `types`, `core` and the facade. It is
  released as the three next-minor versions listed in Evidence, and the implementation PR contains
  `BREAKING` plus this migration table:

  | Removed public spelling | Replacement |
  |---|---|
  | `rustfs_gateway_types::ErrorContext { .. }`, contextual `status_of`, `mask_for_authorization` | a core `ErrorContext` named constructor followed by the sole `resolve` entry |
  | `is_head` or `method` fields | `ResponseKind::Head` supplied once at resolution |
  | `S3Error::new`, `with_status`, `closing`, `about_resource` | build/validate `ErrorContext`, call `resolve`, then use `S3Error::from(ErrorResolution)`; typed transport code uses private converters |
  | the nine current `From<X> for S3Error` implementations | only `From<ErrorResolution> for S3Error`; `FrozenHeader` converts to `HandlerError`, and the other typed paths are private |
  | `StageFilter` and filter closures returning `Result<(), S3Error>` | return `Result<(), HandlerError>`; the service validates and resolves with the real request method |
  | `HandlerError::status` | `resolve(context, response).status()` |
  | codec conversion followed by `about_resource(member)` | `ErrorContext::codec(error)`, whose resulting resolution owns the checked resource |
- The context-free `ErrorCode` table and its unknown-code `400` fallback remain. The implementation
  does not change the frozen IR, generated dto, model or overlays.
- External compile-fail tests prove that downstream code cannot construct or destructure
  `ErrorContext`, construct `ErrorResolution`, set a status/body/header field, or call an
  individual mask/status stage. They also prove that a `StageFilter` returning `S3Error`, a call to
  any removed `S3Error` writer, and a direct `S3Error::from(HandlerError)` no longer compile. A
  public accessor never returns a mutable collection.
- Dynamic tests cover all eleven P1-04 cases. Negative cases include a missing key without
  ListBucket, DeleteObject with a missing bucket, a delete marker without a version id, a `304`
  plan offered a body, a HEAD plan offered framing, an invalid or overlong region, and an attempt
  to override the canonical CORS message. Extra validation separately covers a control character
  in each dynamic XML detail, every disallowed code-to-extra pair, an incomplete range triple and
  unequal `UnsatisfiedRange`/`ActualObjectSize` lengths. Custom-code tests accept the unknown
  `VendorSpecific` control and reject empty, punctuated, over-128-byte and `U+0001` values. Resource
  tests reject over-128-byte, XML-invalid and non-identifier model-member text.
- Parity tests feed the same resolution through core and the facade and compare status, headers
  and body bytes. Each assertion is mutation-tested, including reversal of masking order and
  insertion of `Content-Length` into `204`, `304` and HEAD.
- A deterministic `check_error_resolution_closed.sh` guard requires private fields, one public
  `resolve` entry, the contextual-code deny set, the complete code-to-extra matrix, no public
  `HandlerError::status`, semantic `S3Error` constructor, `closing` or `about_resource`, the full
  workspace-wide writer/return/re-export inventory above, exactly one public
  `From<ErrorResolution> for S3Error`, no other public `From<X> for S3Error`, and explicit mappings
  for `c-err-n001` through `c-err-n011`. Its self-test reintroduces the `FrozenHeader` conversion,
  changes one `StageFilter` method back to `Result<(), S3Error>`, adds a second public `From`,
  restores each removed writer, and deletes or reopens every other boundary in turn.
- The cost is more named constructors and a coordinated migration. The benefit is that a response
  shape is reviewed once and contradictory combinations no longer typecheck or survive resolution.
