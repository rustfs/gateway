# ADR-0002: dyn and async policy for extension points

- Status: Accepted
- Date: 2026-08-05
- Trigger: RustFS Gateway axiom A4 (extension points are symmetric in granularity)
- Supersedes / Superseded by: none

## Context

RustFS Gateway exposes eleven extension points — `Authorizer`, `HostResolver`,
`SignatureVerifier`, `Observer`, `Governor`, `StageFilter`, `OpLayer<O>` and the
rest. Every one of them is asynchronous, and every one of them is stored in a
`ServiceConfig` and held as `Arc<dyn _>` so that a service can be assembled at
run time from configuration rather than at compile time from a type parameter.
Being usable as a trait object is therefore a hard requirement of the
architecture, not a stylistic preference.

Rust gives four ways to spell an async method on a trait, and they are not
interchangeable. `async fn` in traits (AFIT / RPITIT) has been stable since Rust
1.75 and is the spelling every contributor reaches for first — but it is
explicitly *not* dyn compatible, and the failure does not surface at the
definition site. It surfaces later, in the assembly code, as `E0038`. Without a
written policy, the first agent to implement an extension point writes
`async fn`, the assembly stage fails, and the trait plus every implementation of
it has to be rewritten.

This ADR fixes the spelling once, for all eleven extension points, before any of
them exists.

## Decision

**Every trait that is stored in `ServiceConfig` or held as `Arc<dyn _>` declares
its async methods by hand as `-> BoxFuture<'_, T>`.** No `#[async_trait]`, no
associated `type Fut: Future`, no `async fn` in trait.

**`Handler<O>` and `Operation` are the only two traits permitted to use RPITIT**
(`async fn` in trait). They are erased by a closure at registration time and are
never used as trait objects, so dyn compatibility does not apply to them.

```rust
// The rustfs-gateway facade re-exports this so downstream never defines its own:
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// EVERY extension point looks like this — hand-written, dyn compatible:
pub trait Authorizer: Send + Sync + 'static {
    fn authorize(&self, req: &AuthzRequest<'_>) -> BoxFuture<'_, Result<(), AuthzError>>;
}

// The ONLY two traits allowed to use RPITIT, because they are erased at
// registration time and never used as trait objects:
pub trait Handler<O: Operation>: Send + Sync + 'static {
    async fn call(&self, req: Req<O>) -> Result<Resp<O>>;
}

// What registration erases them into — note there is no `dyn Handler`:
type Erased = Box<dyn Fn(HttpReq) -> BoxFuture<'static, S3Result<HttpResp>> + Send + Sync>;
```

## Evidence

All results below were measured with **rustc 1.97.1 (8bab26f4f 2026-07-14)**
against the API-architecture review probe crates.

**Measured (probe1): giving `Handler` an RPITIT method makes it impossible to
build a trait object.**

```
error[E0038]: the trait `Handler` is not dyn compatible
```

**Measured (probe5): a bundle trait composed of RPITIT traits inherits the same
defect — `FullS3 = Handler<A> + Handler<B> + …`:**

```
error[E0038]: the trait `FullS3` is not dyn compatible
```

**Measured comparison of the four available spellings:**

| Spelling | dyn compatible | rustdoc readability | Forces a macro on downstream | Verdict |
| --- | --- | --- | --- | --- |
| `async fn` in trait (AFIT / RPITIT) | No — **measured E0038** | Good | No | **Permitted only for `Handler<O>` and `Operation`** |
| `#[async_trait]` macro | Yes | Poor — rustdoc shows the rewritten `Pin<Box<dyn Future>>` signature, and the expansion is unreadable | **Yes** — implementors must depend on the macro too | Rejected |
| Associated type `type Fut: Future` | No — a generic trait with an associated type is not dyn compatible | Poor — every implementor must name a future type | No | Rejected |
| **Hand-written `-> BoxFuture<'_, T>`** | **Yes** | **Good — the signature in the docs is the real signature** | **No** | **Adopted** |

**Why the two exceptions are sound**: `Handler<O>` and `Operation` are consumed
by `RouterBuilder::handle`, which wraps each implementation in a closure and
stores the closure. The erased type is `Box<dyn Fn(..) -> BoxFuture<..>>`; the
trait itself never appears behind `dyn`, so the E0038 rule is never reached.
This is a property of the registration design, not a loophole — if a future
change makes `Handler` reachable as a trait object, this exception must be
revisited via a new ADR.

**Related measured result carried over from the dispatch decision:** the
per-operation `Handler<O>` plus erased-registry variant rebuilds in 3.12 s and
produces a 2.80 MB rlib, against 4.11 s and 3.62 MB for a single monolithic
async trait — 24 % faster and 23 % smaller. The dyn policy therefore costs
nothing in build time; it is not a trade against compile speed.

## Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| `async fn` in trait everywhere | Measured `error[E0038]: the trait Handler is not dyn compatible`. Extension points must live in `ServiceConfig` behind `Arc<dyn _>`, so this is disqualifying, not inconvenient |
| `#[async_trait]` on extension points | Works, but rewrites every signature in rustdoc into `Pin<Box<dyn Future<Output = …> + Send + '_>>` with an added lifetime the user never wrote, and it pushes the macro dependency onto every downstream implementor. We would pay a permanent documentation and dependency tax to avoid typing `Box::pin` |
| Associated future type (`type Fut: Future`) | Not dyn compatible either, and it forces every implementor to name a concrete future type — the worst readability of the four options |
| A bundle supertrait for completeness checking | Measured `error[E0038]: the trait FullS3 is not dyn compatible`, and a missing implementation produced **73 separate `E0277` errors** instead of one actionable message. Completeness is checked at run time by `RouterBuilder::require(OperationSet)` instead |
| Make extension points generic instead of `dyn` | Pushes eleven type parameters into `ServiceConfig` and into every user's type signature, monomorphises the whole pipeline per configuration, and makes run-time assembly from configuration impossible |
| Let each extension point choose its own spelling | Guarantees that the one that chose wrong is discovered during assembly, after all its implementations exist. A uniform rule is the entire point of writing this down |

## Consequences

- **The facade crate must re-export the alias.** `rustfs-gateway` exports
  `pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;` so
  that no downstream crate has to take a dependency on `futures` just to name
  the return type of a trait it implements. This is a public API commitment.
- **Every `BoxFuture` extension point ships a closure adapter.** Requiring a user
  to declare a struct in order to supply one function is the real ergonomic cost
  of this decision, and the adapters are what pay it back. A new extension point
  is not complete until its adapter exists.
- **Implementors write `Box::pin(async move { … })`.** That is the visible cost.
  It is accepted because the resulting signature is honest and appears verbatim
  in the documentation.
- **Adding a method to an extension-point trait requires a default
  implementation**, otherwise it is a major breaking change (see ADR-0004).
- **Adding a supertrait is always a major breaking change**, so the supertrait
  set is fixed now, once, for every extension point: `Send + Sync + 'static`.
  Nothing else may be added later without a major version.
- **`Handler<O>` and `Operation` must stay unreachable as trait objects.** Any
  design that would require `dyn Handler` invalidates the exception and requires
  a superseding ADR rather than a quiet edit here.
- **Enforcement is by review, plus the shape of the code itself.** There is no
  practical grep that distinguishes an extension point from any other trait, so
  the guardrail is this document plus the fact that a wrong choice fails to
  compile the moment the trait reaches `ServiceConfig`. Failing loudly at
  assembly time is acceptable *because* the policy is written down; without it,
  the same failure is a redesign.
