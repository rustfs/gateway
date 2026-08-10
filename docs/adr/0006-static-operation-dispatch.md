# ADR-0006: Static operation dispatch across the core-facade boundary

- Status: Accepted
- Date: 2026-08-10
- Trigger: crate boundary
- Supersedes / Superseded by: none

## Context

`rustfs-gateway` currently reaches every operation through closures created by
`ErasedCodec` and `erase_authorized_handler`. That is the right default for a
runtime-built service containing unrelated backend types. It cannot also be the
implementation of `ServiceBuilder::build_monomorphic`: putting a generic facade
around the same table changes the type name but leaves the hot path behind
`Arc<dyn Fn>`.

The typed transitions are owned by `rustfs-gateway-core`. In particular,
`Decoded<O>`, its preparation and authorization transitions, the contents of
`ErasedRequest`, and the only conversion into `Req<O>` are not accessible to the
facade. This is a necessary security boundary: downstream code must not be able
to construct an authorized request. It also means that a real static path needs
an intentional public contract at the core-to-facade boundary; copying the
pipeline into the facade cannot preserve the authorization proof.

## Decision

Add `StaticOperation<O>` to `rustfs-gateway-core` as one sealed public entry
point. Its single public dispatch method takes the actual routed-operation
identity, one concrete backend, and core-owned callback inputs for the facade's
existing authorization and body gates. All typed decode, derived-resource,
authorization, handler-invocation, response-restoration, and encoding helpers
remain `pub(crate)` in core. The entry executes them in the existing order:
route authorization first, then the authorized body read and decode, then
derived-resource input authorization, and only then handler invocation and
encoding. It stores no operation codec or handler function pointer or trait
object.

The entry compares the runtime routed operation identity with `O::NAME` before
any typed transition. A mismatch is a fail-closed internal dispatch error, not
a downcast retry and never permission to continue. Only core creates or opens
the private `Decoded<O>` and `Authorized<O>` values, and no constructor for
either proof-bearing type becomes public. Exposing the individual stages as
separately callable public methods is forbidden because it would let a caller
reorder or omit an authorization transition.

`rustfs-gateway` builds its monomorphic path from an explicit type-level
operation set. Each branch names `O` and calls the sealed entry with one
concrete backend type `H`; the entry still validates the routed identity, so a
wrong type-list branch cannot cross the proof boundary. Generated or
hand-written operation-set code may select the branch, but it may not rewrite
handler bodies. The existing dynamic registry and non-generic `S3Service`
remain the default and retain their current API and behavior. The static facade
is a separate generic service returned by `build_monomorphic`, and the two
paths share routing, security extensions, configuration snapshots, response
shapes, refusal rendering, and the existing `Arc<dyn Authorizer>` and other
extension objects. This decision removes dynamic dispatch only from operation
codec and handler selection; it does not replace the extension-point policy in
ADR-0002.

## Evidence

All compiler results below were measured with `rustc 1.97.1
(8bab26f4f 2026-07-14)` from the repository toolchain.

**Measured:** a temporary `rustfs-gateway` integration probe accepting
`rustfs_gateway_core::ErasedRequest` and calling `request.into_inner()` failed
under `cargo check -p rustfs-gateway --test static_dispatch_visibility_probe`:

```text
error[E0624]: method `into_inner` is private
```

The diagnostic points to `crates/core/src/registry/handlers.rs:78`. The same
file's typed `dispatch<O, B>` is private at line 115.

**Measured:**

```text
$ rg -n '^pub\(crate\) (struct Decoded|fn prepare_input|fn authorize_input)' crates/core/src/authz/mod.rs
383:pub(crate) struct Decoded<O: Operation> {
400:pub(crate) fn prepare_input<O: Operation>(...)
468:pub(crate) fn authorize_input<O, F>(...)
```

These are the three typed steps the facade would have to duplicate or expose to
call `Handler<O>` directly.

**Measured:**

```text
$ rg -n '^type (Invoke|Encode) = Arc<dyn Fn' crates/gateway/src/dispatch.rs
104:type Invoke = Arc<dyn Fn(...
107:type Encode = Arc<dyn Fn(...
```

The current facade therefore has two stored indirect-call sites per operation
in addition to the erased core codec callbacks. A facade-only generic wrapper
would still call both sites [inferred].

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| Return a generic wrapper around the existing `S3Service` | The wrapper still looks up `OperationDispatch` and calls its `Arc<dyn Fn>` members. It changes the public type without changing the measured call path |
| Store each backend as `Any` and downcast it in the facade | A concrete backend is not enough: the facade still cannot turn `ErasedRequest` into the private `Authorized<O>` and then `Req<O>` |
| Reimplement `Decoded`, `Authorized`, or `Req` in the facade | A second proof type would not be accepted by core and would create two authorities for authorization. Making it interoperable would weaken the construction boundary |
| Make the existing proof constructors or erased payload contents public | Downstream code could forge a handler request without completing both authorization stages. The static API must perform transitions, not publish their constructors |
| Publish separate generic methods for decode, authorize, invoke, and encode | A downstream caller could call them out of order or omit one authorization pass. One sealed entry is the smallest API that preserves the pipeline order |
| Move the whole request pipeline into core | The facade owns assembly, hot configuration, extension ordering, panic isolation, and HTTP response unification. Moving those responsibilities is a cross-crate refactor, not the smallest boundary addition |
| Add a core dependency on the facade | This reverses the protocol-kernel dependency direction and creates a cycle |
| Generate facade closures for every operation | Generated closures are still indirect calls and fail the `build_monomorphic` requirement even if their source is generated |

## Consequences

- `rustfs-gateway-core` gains an intentional public generic API. Every method
  needs rustdoc and becomes part of the SemVer review surface under ADR-0004.
- The private fields and constructors of `Decoded<O>`, `Authorized<O>`,
  `ErasedRequest`, and `Req<O>` remain private. Compile-fail tests must prove an
  external crate still cannot construct or open them or call an individual
  static stage.
- Dynamic assembly remains source-compatible and keeps heterogeneous backends.
  Static assembly accepts one concrete backend type and an explicit operation
  set, increasing monomorphized code size in exchange for removing stored
  dispatch callbacks.
- Parity tests must run the same ordinary, committed, event-stream, refusal,
  and panic cases through both assembly paths. They must also mutate a
  type-level branch to name the wrong runtime operation and observe a
  fail-closed identity-mismatch error before decode or invocation. A
  source/assembly guard must show that operation codec and handler dispatch on
  the static branch contain no `Arc<dyn Fn>` load or indirect call; existing
  extension calls such as `Arc<dyn Authorizer>` are explicitly outside that
  guard. A generic return type alone is not evidence.
- No crate is added, removed, or given a new dependency. The boundary changes
  only by adding the generic core API described above.
