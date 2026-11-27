# ADR-0056: Seal bearer and header-token verdict and receipt construction

- Status: Accepted
- Date: 2026-11-27
- Trigger: crate boundary and axiom A2 (unsafe spellings must fail to compile); sealing bearer and header-token verdict, receipt, floor-claim, and context construction across `rustfs-gateway-sig`, `rustfs-gateway-core`, `rustfs-gateway-dialect-rustfs-admin`, and `rustfs-gateway` (rustfs/gateway#1574).
- Supersedes / Superseded by: none

## Context

ADR-0042, ADR-0046, and ADR-0054 added two host-verified token authentication kinds: a route-bound
query bearer claim (`QueryBearerClaim`, `BearerAdmission`, `BearerReceipt`, `Verdict::Bearer`) for
RustFS's minted zip-download URLs, and a service-level header token claim (`HeaderTokenClaim`,
`HeaderTokenAdmission`, `HeaderTokenReceipt`, `Verdict::HeaderToken`) for outer-layer tokens such
as OpenStack Keystone's `X-Auth-Token`. Both receipts have private fields, no `Clone` or `Default`,
and crate-private `Verdict` constructors (`Verdict::bearer` and `Verdict::header_token`) inside
`rustfs-gateway-sig`.

Both ADR-0046 and ADR-0054 recorded the same residual, tracked in
[issue #1574](https://github.com/rustfs/gateway/issues/1574): the methods that turn an admission
into a verdict or receipt, extract a bearer admission alongside a signature, attach a query bearer
claim to an operation floor, and mutate a `RequestContextView` for a bearer receipt remain public
items because `rustfs-gateway-sig` (Ring 0), `rustfs-gateway-core` (Ring 1),
`rustfs-gateway-dialect-rustfs-admin` (Ring 1), and `rustfs-gateway` (Ring 1 facade) are separate
crates:

- `BearerAdmission::verify` (`crates/sig/src/bearer.rs`) builds `Verdict::Bearer` for any verifier
  and raw path the caller supplies.
- `BearerAdmission::verify_alongside` (`crates/sig/src/bearer.rs`) builds `BearerReceipt` against
  any caller-constructed `Identity` rather than requiring a signature-authenticated `Verdict`.
- `SecurityFloor::bearer_alongside_signature` (`crates/sig/src/floor_bearer.rs`) yields a
  `BearerAdmission` directly from a `WireView` without the AWS-surface gate that
  `SecurityFloor::admit` applies.
- `HeaderTokenAdmission::verify` (`crates/sig/src/header_token.rs`, shared `#1574` residual in
  ADR-0054) builds `Verdict::HeaderToken` for any verifier and `TransportExtensions` the caller
  supplies.
- `OperationFloor::with_query_bearer_claim` (`crates/sig/src/operation.rs`) and
  `rustfs_gateway_dialect_rustfs_admin::admin::zip_token_floor`
  (`crates/dialect-rustfs-admin/src/admin.rs`) let external callers construct an `OperationFloor`
  carrying a `QueryBearerClaim` for any operation name.
- `RequestContextView::with_bearer_receipt` and `RequestContextView::without_bearer_token`
  (`crates/core/src/request_context.rs`) are public mutators on a read-only handler context; the
  first attaches a receipt without checking that the context is signature-authenticated, matches
  the receipt's operation and principal, or lacks an existing bearer context, and the second leaves
  token stripping as an optional caller-remembered step after `RequestContextView::from_pipeline`.

Today, only the facade's run-time check `host_tokens::from_own_admission`
(`crates/gateway/src/service/host_tokens.rs`, fed by `bearer_admitted` and `header_token_admitted`
in `crates/gateway/src/service/authenticate.rs`) keeps a host-minted token verdict out of another
request's pipeline. Host code can mint a verdict or receipt, even though it cannot use one to admit
an unrelated request.

Issue #1574 also leaves one calling-contract question open: `BearerTokenVerifier::verify` (and its
sibling `HeaderTokenVerifier::identity`) runs synchronously on the request path with a documented
non-blocking contract, and must either stay synchronous or gain an async/deadline seam.

## Decision

Remove every public verdict-minting, receipt-minting, alongside-extraction, bearer-claim-attaching,
and bearer-context-mutating inherent method named above from the public API of `rustfs-gateway-sig`,
`rustfs-gateway-core`, `rustfs-gateway-dialect-rustfs-admin`, and `rustfs-gateway`, and move the
cross-crate calls behind a single `#[doc(hidden)]` internal facade bridge gated by a zero-sized
`FacadeSeal` capability token that `rustfs-gateway` never re-exports, backed by a deterministic CI
guard script and while keeping every run-time `from_own_admission` check intact. Keep
`BearerTokenVerifier::verify` and `HeaderTokenVerifier::identity` synchronous with no kernel-side
verifier deadline. Do not add a crate, reverse any Ring 0/1 dependency edge, introduce `unsafe`,
add `inventory`/`linkme`, or modify any existing ADR.

**Why a single `#[doc(hidden)]` bridge plus deterministic guard is the exact Rust boundary.** Rust
has no cross-crate `friend` visibility: `pub(crate)` in `rustfs-gateway-sig` or `rustfs-gateway-core`
is invisible to `rustfs-gateway`, and neither Ring 0 `sig` nor Ring 1 `core` may depend on
`rustfs-gateway` (`scripts/check_layer_dependencies.sh`). Any cross-crate bridge callable by
`rustfs-gateway` must therefore remain `pub` in the lower crate. Moving those operations out of the
inherent public surfaces into a `#[doc(hidden)]` module gated by `FacadeSeal` — never re-exported
by `rustfs-gateway` or `rustfs-gateway::sig` — makes every old spelling fail to compile for all
facade consumers and for direct consumers of `sig`/`core`, while giving one greppable symbol
(`__facade_internal`) for a deterministic CI guard to police across the workspace.

**Signature-crate sealing (`rustfs-gateway-sig`).**
1. Remove the public inherent methods `BearerAdmission::verify`, `BearerAdmission::verify_alongside`,
   `SecurityFloor::bearer_alongside_signature`, `HeaderTokenAdmission::verify`, and
   `OperationFloor::with_query_bearer_claim`. Keep their core implementations `pub(crate)` inside
   `rustfs-gateway-sig` so unit tests in `crates/sig` continue exercising ADR-0042, ADR-0046, and
   ADR-0054 directly without widening visibility.
2. Add one `#[doc(hidden)] pub mod __facade_internal` in `crates/sig/src/lib.rs` containing a
   `#[doc(hidden)]` zero-sized capability token `FacadeSeal` (private field, `const fn new()`) and
   exactly four forwarding functions:
   - `verify_bearer(seal: FacadeSeal, admission: BearerAdmission, verifier: &dyn BearerTokenVerifier, raw_path: &str) -> Verdict`
     (called in production only by `crates/gateway/src/service/host_tokens.rs`).
   - `verify_bearer_alongside_signature(seal: FacadeSeal, floor: &SecurityFloor, view: &WireView<'_>, operation: &OperationFloor, now: RequestNow, signed_verdict: &Verdict, verifier: &dyn BearerTokenVerifier, raw_path: &str) -> Result<BearerReceipt, AuthError>`
     (called in production only by `crates/gateway/src/service/authenticate.rs`). Merging
     `bearer_alongside_signature` and `verify_alongside` into one atomic function eliminates any
     detached `BearerAdmission` bypassing `SecurityFloor::admit`'s AWS-surface gate and requires an
     authenticated `Verdict::Authenticated { identity, .. }` (carrying a real `SignatureMatch`)
     inside `rustfs-gateway-sig` rather than trusting a caller-supplied `&Identity`; any
     non-authenticated verdict returns `Err(AuthError::AccessDenied)` before reading the token or
     calling the verifier.
   - `verify_header_token<V: HeaderTokenVerifier>(seal: FacadeSeal, admission: HeaderTokenAdmission, verifier: &V, server_state: &TransportExtensions) -> Verdict`
     (called in production only by `crates/gateway/src/builder/host_tokens.rs` inside the erased
     `HeaderTokenVerify` closure). `Identity::host_reported()` remains `pub(crate)` in
     `rustfs-gateway-sig`.
   - `const fn with_query_bearer_claim(seal: FacadeSeal, floor: OperationFloor, claim: QueryBearerClaim) -> OperationFloor`
     (called in production only by `crates/dialect-rustfs-admin/src/admin.rs`). `OperationFloor::query_bearer_claim`
     remains a public read-only accessor so `core`, `sig`, and `gateway` posture reporting keep
     reading it.
3. Store `claim: QueryBearerClaim` privately on `BearerReceipt` and expose a read-only
   `pub const fn claim(&self) -> QueryBearerClaim` accessor (static parameter name and path suffix
   only; never the token).
4. Keep `SecurityFloor::with_header_token_claim` public because it mints neither a verdict nor a
   receipt and preserves ADR-0054's tested `AssemblyError::HeaderTokenClaimWithoutVerifier`
   assembly check.
5. `rustfs-gateway` and `rustfs-gateway::sig` MUST NOT re-export `__facade_internal`, `FacadeSeal`,
   `Admission`, `BearerAdmission`, `BearerReceipt`, `HeaderTokenAdmission`, `HeaderTokenReceipt`,
   `QueryBearerClaim`, or `WireView`.

**Dialect-crate sealing (`rustfs-gateway-dialect-rustfs-admin`).** Narrow `admin::zip_token_floor`
(`crates/dialect-rustfs-admin/src/admin.rs`) from `pub const fn` to `pub(crate) const fn` so
external callers cannot use the admin dialect crate to mint bearer-claimed `OperationFloor` values
for arbitrary operation names. `admin::ZIP_DOWNLOAD_TOKEN` may stay a read-only constant descriptor
because a `QueryBearerClaim` value alone cannot attach itself to an `OperationFloor`.

**Core-crate context sealing (`rustfs-gateway-core`).**
1. Remove both public mutators `RequestContextView::with_bearer_receipt` and
   `RequestContextView::without_bearer_token`.
2. In `RequestContextView::from_pipeline`, whenever `verdict` is `Verdict::Bearer(receipt)`,
   automatically strip `receipt.claim()` from `raw_query` during construction so a bearer-verdict
   handler context can never be constructed with the raw token still in `raw_query`.
3. Add `#[doc(hidden)] pub mod __facade_internal` in `crates/core/src/lib.rs` with a
   `#[doc(hidden)]` `FacadeSeal` token and one atomic helper
   `attach_signed_bearer_receipt(seal: FacadeSeal, context: RequestContextView, receipt: &BearerReceipt) -> RequestContextView`
   (called in production only by `crates/gateway/src/service.rs`). It attaches
   `BearerContext::of(receipt)` and strips `receipt.claim()` from `context.raw_query` in one step,
   and enforces fail-closed invariants mirroring `with_post_object_key_constraints`: the context must
   carry a signed `principal`, have no existing `bearer` context, match `receipt.operation()`, and
   match `receipt.identity().access_key_id() == principal.access_key_id()`; otherwise it leaves
   `context.bearer` unchanged (`None`). Because every non-refused request on a bearer-claimed
   operation with an installed verifier either produces `Verdict::Bearer(receipt)`, produces
   `signed_bearer = Some(receipt)`, or arrived anonymously with zero occurrences of the claim
   parameter, `without_bearer_token` is eliminated completely.

**Retain run-time defense in depth (`rustfs-gateway`).** Keep `host_tokens::from_own_admission`
(`bearer_admitted` and `header_token_admitted` in `crates/gateway/src/service/authenticate.rs` and
`crates/gateway/src/service/host_tokens.rs`) unchanged. Because a crate depending directly on
`rustfs-gateway-sig` could deliberately name `__facade_internal`, the run-time admission-arm binding
remains the mandatory second wall, and the existing reuse tests
(`a_custom_verifier_cannot_reuse_another_bearer_admission`,
`concurrent_custom_requests_cannot_reuse_bearer_admissions`, and
`n_a_header_token_verdict_from_another_admission_authenticates_nothing`) remain intact as explicit
fault-injection probes proving the run-time wall still holds even if the `#[doc(hidden)]` bridge is
bypassed.

**Synchronous verifier contract — no async seam or kernel deadline.** Keep
`BearerTokenVerifier::verify` and `HeaderTokenVerifier::identity` synchronous with no per-call
timeout or `spawn_blocking` wrapper:
- `rustfs-gateway-sig` is a Ring-0 synchronous state machine with zero async runtime dependencies;
  adding `BoxFuture` to `BearerTokenVerifier` would either pull async types into Ring 0 or push
  verification out of `sig` (exposing raw token bytes and `Identity::host_reported()` across crate
  boundaries).
- A Rust async timeout (`futures_timer` / `tokio::time::timeout`) cannot preempt a blocking
  synchronous call, and wrapping an unauthenticated endpoint's verifier in `spawn_blocking` breaks
  the gateway's runtime-independent deadline architecture (`crates/gateway/src/request_deadline.rs`),
  copies secret token bytes across threads, and opens a blocking-pool exhaustion DoS vector.
- Measured host workloads need no async verifier I/O: RustFS's ADR-0042 zip verifier performs
  in-memory AEAD decryption, and ADR-0054's Keystone flow already performs async remote token
  validation in an outer `tower::Layer` (where the host owns its timeout and circuit breaker) and
  passes only the validated `Established` value via `TransportExtensions`. Post-auth async liveness
  and policy checks already run through `PolicySource` (with `PolicyTimeout`) and `Authorizer`
  (`BoxFuture`, ADR-0002).
- Reopen trigger: only if a future route-bound query bearer claim genuinely requires async remote
  introspection that cannot run in an outer layer before routing may a new ADR introduce a separate
  facade-level async verifier trait using ADR-0002's `BoxFuture<'_, ...>` and a runtime-independent
  `futures_timer` deadline.

## Evidence

- *measured* (`rustc --version`): workspace toolchain is `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- *measured* (`git rev-parse origin/main` and `ls docs/adr/`): baseline commit is
  `29f1a59b3132b8940b9130de46ef7c4c9ae1b5f1`; the highest existing ADR is `0055`, so this record is
  `0056`.
- *measured* (source audit at `29f1a59b` via `rg` across `crates/`): the exact target definitions
  and production callers are:
  - `BearerAdmission::verify` (`crates/sig/src/bearer.rs:236`) — single production caller
    `crates/gateway/src/service/host_tokens.rs:95`.
  - `BearerAdmission::verify_alongside` (`crates/sig/src/bearer.rs:272`) — single production caller
    `crates/gateway/src/service/authenticate.rs:409`.
  - `SecurityFloor::bearer_alongside_signature` (`crates/sig/src/floor_bearer.rs:85`) — single
    production caller `crates/gateway/src/service/authenticate.rs:405`.
  - `HeaderTokenAdmission::verify` (`crates/sig/src/header_token.rs:302`, ADR-0054 `#1574`
    residual) — single production caller `crates/gateway/src/builder/host_tokens.rs:111`.
  - `OperationFloor::with_query_bearer_claim` (`crates/sig/src/operation.rs:369`) — single
    production caller `crates/dialect-rustfs-admin/src/admin.rs:279` (via
    `admin::zip_token_floor` at line 276, itself called only by
    `crates/dialect-rustfs-admin/src/ops/get_v3_object_zip_downloads_by_id_zip.rs:96`).
  - `RequestContextView::with_bearer_receipt` (`crates/core/src/request_context.rs:488`) and
    `RequestContextView::without_bearer_token` (`crates/core/src/request_context.rs:496`) — single
    production caller `crates/gateway/src/service.rs:1403` and `1407`.
- *measured* (`crates/gateway/src/lib.rs:224-227,517-521` and `crates/gateway/src/sig.rs:39-59`):
  `rustfs-gateway` re-exports `SecurityFloor`, `OperationFloor`, `RequestContextView`, `Verdict`,
  `BearerTokenVerifier`, and `HeaderTokenVerifier`, and already omits `Admission`,
  `BearerAdmission`, `BearerReceipt`, `HeaderTokenAdmission`, `HeaderTokenReceipt`,
  `QueryBearerClaim`, and `WireView`.
- *measured* (`crates/core/src/request_context.rs:566`, `crates/core/src/request_context_post.rs:34`,
  `crates/core/src/static_dispatch.rs:122,261`): `rustfs-gateway-core` already uses `#[doc(hidden)]`
  combined with fail-closed invariant checks (`with_post_object_key_constraints`) for facade-only
  context attachments across the `core`–`gateway` crate boundary.
- *measured* (`crates/sig/Cargo.toml`): `rustfs-gateway-sig` is `ring = 0` and has zero `futures`
  or `tokio` dependencies (`rg -n 'futures|tokio' crates/sig/Cargo.toml` returned 0 matches).
- *measured* (`crates/gateway/src/service/authenticate.rs:209,273,326,354` and
  `crates/gateway/src/service/host_tokens.rs:149-157`): `from_own_admission` rejects any
  `Verdict::Bearer` when `!bearer_admitted` and any `Verdict::HeaderToken` when
  `!header_token_admitted`; `crates/gateway/tests/custom_signature_verifier.rs:375,443` and
  `crates/gateway/tests/header_token.rs:394` exercise this check by importing `rustfs_gateway_sig`
  directly and forging verdicts via the currently public methods.
- `[inferred]` Because Rust (`rustc 1.97.1`) provides no cross-crate `friend` visibility modifier
  and `scripts/check_layer_dependencies.sh` forbids `sig -> gateway` and `core -> gateway` edges,
  a `#[doc(hidden)]` capability-gated internal bridge combined with a deterministic workspace guard
  script and preserved run-time admission-arm binding is the strongest boundary enforceable without
  collapsing crates or leaking secrets across crate boundaries. No implementation code or `trybuild`
  probe has been compiled in this ADR-only change.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Move bearer and header-token verification and receipts out of `rustfs-gateway-sig` into `rustfs-gateway` | Either exposes raw `Zeroizing<String>` bearer tokens and `pub fn Identity::host_reported()` publicly from `sig` (breaking ADR-0054's `E0624` guarantee), or removes `Verdict::Bearer` and `Verdict::HeaderToken` and forces `rustfs-gateway-core::RequestContextView` to accept raw unproved `Identity` values (violating ADR-0042 and ADR-0046). |
| Gate the bridge behind a Cargo feature flag (e.g. `sig/facade-internal`) instead of `#[doc(hidden)]` + guard script | Cargo features are additive and unified across the dependency graph: any host crate depending on `rustfs-gateway` automatically receives `sig/facade-internal` enabled, giving the illusion of exclusivity while compiling identically for direct `sig` dependents. |
| Add a shared private workspace crate (e.g. `crates/internal-seal`) for the capability token | Any crate depended on by both `sig` and `gateway` is equally reachable to any consumer of the git workspace, while adding a new crate and changing `scripts/check_layer_dependencies.sh` for zero additional compiler enforcement. |
| Merge `rustfs-gateway-sig` or `rustfs-gateway-core` into `rustfs-gateway` so `pub(crate)` spans them | Destroys the Ring 0 / Ring 1 separation in `AGENTS.md` and creates cycles with `rustfs-gateway-core`, `rustfs-gateway-dialect-rustfs-admin`, and `rustfs-gateway-dialect-minio`. |
| Keep `SecurityFloor::bearer_alongside_signature` and `BearerAdmission::verify_alongside` as two separate internal functions taking `&Identity` | Allows a detached `BearerAdmission` bypassing `SecurityFloor::admit` and lets callers pass an arbitrary `Identity::new(...)` instead of a verified `Verdict::Authenticated` carrying a `SignatureMatch`. |
| Keep `OperationFloor::with_query_bearer_claim` and `admin::zip_token_floor` public | Leaves external crates able to declare arbitrary query-string bearer claims (URL-borne credentials) outside ADR-0042's reviewed zip-download scope and synthesize bearer admissions via `SecurityFloor::admit`. |
| Make `BearerTokenVerifier::verify` async (`BoxFuture`) or wrap sync calls in `tokio::task::spawn_blocking` with a timeout | `rustfs-gateway-sig` is a synchronous Ring-0 crate with no async dependencies; async timeouts cannot preempt blocking sync code; `spawn_blocking` breaks runtime independence (`request_deadline.rs`), copies secret tokens across threads, and creates an unauthenticated blocking-pool exhaustion DoS vector when no host requires async I/O inside `BearerTokenVerifier`. |
| Drop the run-time `from_own_admission` (`bearer_admitted` / `header_token_admitted`) check once the methods are sealed | Because `#[doc(hidden)]` does not prevent a direct `rustfs-gateway-sig` dependent from spelling `__facade_internal`, removing the run-time check would turn a defense-in-depth boundary into a single point of failure. |

## Consequences

This ADR is documentation-only and introduces no runtime changes; it must merge before the
cross-crate implementation PR for rustfs/gateway#1574 lands (`AGENTS.md`: never refactor across a
crate boundary without an ADR merged first).

**SemVer and migration (ADR-0004).** Removing the public inherent methods from `rustfs-gateway-sig`,
`rustfs-gateway-core`, and `rustfs-gateway-dialect-rustfs-admin` is a source-breaking change for
direct consumers of those items during `0.x`. The implementation PR must bump the minor versions of
`rustfs-gateway-sig`, `rustfs-gateway-core`, `rustfs-gateway-dialect-rustfs-admin`, and
`rustfs-gateway`, mark the PR description `BREAKING`, and state the migration:
- Embedding hosts installing verifiers via `ServiceBuilder::bearer_token_verifier` and
  `ServiceBuilder::host_verified_header_token` and reading `RequestContextView::bearer()` or
  `RequestContextView::header_token_principal()` require zero source changes.
- Callers that previously invoked `BearerAdmission::verify`, `BearerAdmission::verify_alongside`,
  `SecurityFloor::bearer_alongside_signature`, `HeaderTokenAdmission::verify`,
  `OperationFloor::with_query_bearer_claim`, `admin::zip_token_floor`,
  `RequestContextView::with_bearer_receipt`, or `RequestContextView::without_bearer_token` directly
  must route requests through `S3Service` (and register the RustFS admin dialect via
  `rustfs_admin_dialect()`).

**Residual explicitly accepted.** Because `rustfs-gateway-sig`, `rustfs-gateway-core`,
`rustfs-gateway-dialect-rustfs-admin`, and `rustfs-gateway` remain separate crates, a crate that
bypasses the `rustfs-gateway` facade, depends directly on `rustfs-gateway-sig` or
`rustfs-gateway-core`, and deliberately names `__facade_internal` can still compile a call to the
bridge. Two independent controls bound that residual: (1) inside this workspace, a deterministic CI
guard rejects any reference outside the allowlisted facade/dialect modules and explicit
fault-injection tests; and (2) at run time, `host_tokens::from_own_admission` still refuses any
bearer or header-token verdict that did not originate from the current request's own floor
admission arm, and `attach_signed_bearer_receipt` still rejects mismatched operations, mismatched
principals, or unauthenticated contexts.

**Verification, guardrails, and required mutations for the `#1574` implementation PR.**
1. **New deterministic guard script (`scripts/check_token_sealing_surface.sh`)**, wired into CI
   static checks and `scripts/test_guard_scripts.sh`, asserting:
   - None of `BearerAdmission`, `HeaderTokenAdmission`, `SecurityFloor`, `OperationFloor`, or
     `RequestContextView` declares a public inherent `verify`, `verify_alongside`,
     `bearer_alongside_signature`, `with_query_bearer_claim`, `with_bearer_receipt`, or
     `without_bearer_token` method, and `admin::zip_token_floor` is not `pub`.
   - `rustfs-gateway` (`crates/gateway/src/lib.rs` and `crates/gateway/src/sig.rs`) never
     re-exports `__facade_internal`, `FacadeSeal`, `Admission`, `BearerAdmission`,
     `HeaderTokenAdmission`, `BearerReceipt`, `HeaderTokenReceipt`, `QueryBearerClaim`, or
     `WireView`.
   - References to `__facade_internal` appear only in the exact allowlisted production sites
     (`crates/gateway/src/service/host_tokens.rs`, `crates/gateway/src/service/authenticate.rs`,
     `crates/gateway/src/builder/host_tokens.rs`, `crates/gateway/src/service.rs`,
     `crates/dialect-rustfs-admin/src/admin.rs`) and explicitly allowlisted fault-injection tests.
   - Guard self-test plants a forbidden reference / public method and confirms the guard exits
     non-zero.
2. **Compile-fail negative tests (`trybuild` + rustdoc `compile_fail`).** Preserve all existing
   `compile_fail` doctests in `crates/sig/src/bearer.rs` and `crates/sig/src/header_token.rs` (so
   `scripts/check_ct_eq.sh`'s `COMPILE_FAIL_FLOOR` never drops) and add `trybuild` `compile_fail`
   cases covering:
   - Calling `BearerAdmission::verify`, `BearerAdmission::verify_alongside`,
     `SecurityFloor::bearer_alongside_signature`, `HeaderTokenAdmission::verify`, and
     `OperationFloor::with_query_bearer_claim` against `rustfs_gateway_sig` (separate `#[test]` in
     `crates/sig/tests/compile_fail.rs`).
   - Calling `RequestContextView::with_bearer_receipt` and
     `RequestContextView::without_bearer_token` against `rustfs_gateway_core` and `rustfs_gateway`
     (note: `scripts/check_error_resolution_surface.sh` pins the exact call inventory inside
     `compile_time_contracts_are_not_openable` and `gateway_compile_fail_contracts_are_enforced`,
     so add dedicated `#[test]` harness functions or update the guard inventory explicitly).
   - Attempting to import `__facade_internal`, `FacadeSeal`, `BearerAdmission`,
     `HeaderTokenAdmission`, `BearerReceipt`, `HeaderTokenReceipt`, or `QueryBearerClaim` from
     `rustfs_gateway` or `rustfs_gateway::sig`.
3. **Run-time unit and integration tests (negative > positive).**
   - Verify `verify_bearer_alongside_signature` refuses `Verdict::Anonymous`, `Verdict::Bearer`,
     `Verdict::HeaderToken`, and `Verdict::Reject` with `AuthError::AccessDenied` without calling
     the verifier, and accepts only a matching `Verdict::Authenticated`.
   - Verify `RequestContextView::from_pipeline` strips the bearer token automatically from
     `raw_query` for `Verdict::Bearer`.
   - Verify `attach_signed_bearer_receipt` refuses (leaves `bearer()` `None`) on detached,
     anonymous, wrong-operation, wrong-principal, and already-bearer contexts, and both attaches
     and strips the token on a matching signed context.
   - Keep `a_custom_verifier_cannot_reuse_another_bearer_admission`,
     `concurrent_custom_requests_cannot_reuse_bearer_admissions`, and
     `n_a_header_token_verdict_from_another_admission_authenticates_nothing` green as run-time
     defense-in-depth tests.
4. **Required deliberate red mutations.** The implementation PR must record deliberate mutations
   turning each new check red: restoring public visibility on any sealed method turns its
   `compile_fail` probe and `check_token_sealing_surface.sh` red; removing the
   `Verdict::Authenticated` guard in `verify_bearer_alongside_signature` turns its negative tests
   red; removing automatic stripping in `from_pipeline` or invariant checks in
   `attach_signed_bearer_receipt` turns the secrecy/context tests red; and disabling
   `from_own_admission` turns the foreign-verdict reuse tests red.
5. **Gate.** Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`, and `cargo xtask verify --all` (cross-crate wiring), plus
   `scripts/check_token_sealing_surface.sh` and `scripts/test_guard_scripts.sh`.
