# CORS

Why the preflight branch is shaped the way it is. [docs/security-model.md](security-model.md)
covers the signature and secret-handling declarations; this file covers the one endpoint that is
answered without a signature on purpose.

CORS has two halves and they landed separately. The **configuration codec** —
`GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, and what a stored document may say — is
`crates/core/src/ops/shared/cors.rs`. The **runtime** — what a browser is told when it asks — is
`crates/core/src/cors/`, and it is what this file is about.

## The one thing that makes this endpoint different

A CORS preflight carries no credentials. The Fetch Standard forbids a browser from sending any,
so requiring a signature here does not harden the endpoint — it switches CORS off. Every other
request this gateway answers has passed the security floor before anything expensive happens;
this one has passed nothing.

Two consequences follow, and the whole design is those two consequences:

1. **Anything the preflight branch does, an anonymous caller can make it do, for free, as often
   as they like.** A configuration read per request is an amplifier: one cheap HTTP request buys
   one storage round trip.
2. **Anything the preflight branch says, it says to an anonymous caller.** A refusal that differs
   between a bucket that exists and one that does not is a private-bucket enumeration oracle,
   readable with a browser and no account.

## Where it intercepts, and why exactly there

```text
accept ──▶ resolve host ──▶ ★ CORS preflight? ──▶ route ──▶ govern ──▶ admit ──▶ …
                                  │
                                  └─ yes: govern, read, match, answer. Nothing below runs.
```

**After acceptance**, so a preflight is subject to the same wire-level refusals as everything
else. A smuggled or over-long request head must not become answerable by adding an `Origin`.

**After host resolution**, because *which bucket this is* is the `HostResolver`'s answer and not
the pipeline's. The resolver stays synchronous and store-free; the preflight branch is where the
read happens, which is precisely why the read could not be moved into the resolver.

That answer is load-bearing rather than decorative. On a virtual-hosted request the host names the
bucket and the **whole path is the object key**, so `ResolvedHost::bucket()` wins over the path and
the path is consulted only when the resolver reports path-style addressing. Reading the first path
segment on a virtual-hosted preflight would answer `OPTIONS https://b.s3.example.com/key.txt` out
of a bucket called `key.txt` — a cross-tenant confusion the caller constructs by choosing the path
— and `OPTIONS https://b.s3.example.com/` would find no segment at all and refuse every browser
preflight against a virtual-hosted bucket. `conformance/cases/cors/c-cors-0048` and `c-cors-0049`
are the two halves.

**Before routing**, because the route table has no `OPTIONS` row and never will. A preflight is
answered *instead of* an operation, out of the bucket's stored document. Routing it would answer
a CORS question with a `501`, which is what happens today if the branch is removed —
`conformance/cases/cors/c-cors-0043` pins that `501` for the `OPTIONS` that is *not* a preflight,
so the two behaviours are held apart by cases rather than by intent.

Nothing below the branch runs for a preflight: no security floor, no authenticator, no
authorizer, no handler. `crates/gateway/tests/cors_runtime.rs` asserts the last of those by
counting, and `conformance/cases/cors/c-cors-0045` asserts that an allowed preflight grants the
request it described exactly nothing.

## The unauthenticated read, bounded

Inside the branch the order is fixed and may not be rearranged:

| Step | What it is for |
| --- | --- |
| 1. `Governor::try_acquire`, under the name `CorsPreflight` | The rate bound. First, and unconditional — including for a bucket name that is not a legal one, because skipping it there would make that case measurably cheaper than the others |
| 2. `CachedCorsSource::get` | The only path to the deployment's `CorsSource`. `ServiceBuilder::cors_source` takes a bare source and stores a wrapped one; there is no setter that accepts an unwrapped source and no accessor that hands the inner one back |
| 3. `answer_preflight` | One allowance or one refusal |

The cache is a bound rather than a speed-up, and three properties are what make it one:

- **A negative entry has the same shape as a positive one.** "No document", "no bucket" and "the
  source failed" are all stored as the same `None`, so the second probe for a name that does not
  exist costs what the second probe for a configured bucket costs. Without negative caching the
  enumeration probe is also the amplifier.
- **The entry count is capped** (4096 by default). A caller inventing a million bucket names
  evicts their own earlier entries instead of growing the process.
- **Expiry is spread.** Each key's lifetime is the TTL plus an offset derived from the key, so a
  burst of misses admitted in one second does not expire in one second.

**What is not there: single-flight.** A thousand concurrent misses for one uncached bucket are a
thousand reads. Collapsing them needs an async notification primitive `rustfs-gateway` does not
depend on, and a hand-rolled one on the pre-authentication path is where the next defect would
live. The concurrency bound in the meantime is the `Governor`, which runs first. This is a gap,
and it is written here rather than papered over.

**What the defaults cost.** `NoCors` is the default source, so no preflight is ever allowed and
there is nothing to amplify. The governor default is no longer `Unlimited`: `DefaultGovernor`
meters preflights through aggregate, per-client, and CORS-class buckets — see
`docs/capacity-planning.md` — so a deployment that installs a real source has a bound before it
configures one. The client key must come from a listener or trusted-proxy adapter; no forwarding
header is trusted here.

## The response matrix

| Situation | Answer |
| --- | --- |
| A rule matches | `200`, `Access-Control-Allow-Origin`, `-Allow-Methods`, `-Allow-Headers` (when the caller asked about any), `-Max-Age` and `-Expose-Headers` (when the rule sets them), `Vary: Origin`, empty body |
| A document exists and no rule matches | `403 AccessForbidden`, `CORSResponse: …` |
| The bucket exists and has no document | the same response |
| The bucket does not exist | the same response |
| The bucket name is not a legal one | the same response |
| The source failed or timed out | the same response |
| The `Origin` is repeated, empty, over-long, or carries a byte that could end a header line | the same response |

"The same response" means the same bytes: `crates/core/src/cors/preflight_refusal` takes no
arguments and its message is a `&'static str`, so the paths cannot drift apart and none of them
can carry a bucket name. `conformance/cases/cors/c-cors-0034` through `c-cors-0041` and
`c-cors-0046` assert the identical body against the identical string.

There is deliberately no `404`. It is the answer a developer asks for and it is the oracle.

## Reflected `Origin`, and the one combination that is unwritable

`GHSA-x5xv-223c-8vm7` is one sentence: a gateway that echoes the caller's `Origin` and also
answers `Access-Control-Allow-Credentials: true` has told every site on the internet that it may
read this user's objects with this user's session.

A rule's `<AllowedOrigin>` can match in three ways, and the three answer differently:

| The rule said | `Access-Control-Allow-Origin` | Credentials available |
| --- | --- | --- |
| `*` | the literal `*` | never |
| `https://*.example.com` | the caller's own `Origin`, verbatim | never |
| `https://app.example.com` | that origin | only if the deployment's `CorsPolicy` enumerates it |

The bare `*` answers `*` rather than reflecting, because a browser refuses `*` beside credentials
outright — answering it makes the dangerous combination unreachable at the far end too. A partial
wildcard *cannot* answer `*`: that would widen `https://*.example.com` from one operator's
subdomains to every origin there is. So it reflects, and reflection is exactly the case that may
never carry credentials.

The exclusion is enforced three times over, on purpose:

1. **Construction.** `CorsPolicy::new(CorsOrigins::Any, true)` returns `Err`, and so does an
   exact allow-list with a `*` in it. A policy that permits a reflected origin to carry
   credentials does not exist, so no code path can consult one.
2. **Control flow.** `ACCESS_CONTROL_ALLOW_CREDENTIALS` is named in one function,
   `credentials_header`, reachable only from the `AllowOrigin::Exact` arm of `credentials_for`.
   The two wildcard arms return `None` without calling it.
3. **Text.** `scripts/check_cors_credentials_exclusive.sh` refuses a source tree in which any
   function names both the credentials header and a wildcard `AllowOrigin` variant, in which a
   second function names the header at all, or in which the variants are imported unqualified so
   that the first rule would stop matching. All four rules have negative controls in
   `scripts/test_guard_scripts.sh`.

The S3 CORS document has no element for credentials. An operator who wants them says so in the
deployment's `CorsPolicy`, by naming the origins.

## `Vary: Origin`

On every answer this runtime touches, including the refusal. The response depends on `Origin`
even when it does not name one — whether any `Access-Control-*` header is present at all is
decided by it — and RFC 9110 §12.5.5 is what stops a shared cache from handing one origin the
allowance granted to another.

## The ordinary request

A request that is not a preflight is served normally and decorated afterwards. The decoration is
computed **after authorisation**, which is the whole reason an anonymous `GET` carrying an
`Origin` costs no configuration read; `crates/gateway/tests/cors_runtime.rs` counts that to zero
and counts the authorised path to one, so the zero is not the zero of a source nobody calls.

The consequence is worth stating plainly: a request refused *before* authorisation — a bad
signature, an unknown key — carries no CORS headers, and a browser therefore reports it to the
page as an opaque network error rather than as a `403`. That is the cost of not doing an
unauthenticated read, and it is the trade this design makes deliberately. Everything from
authorisation onwards does carry the headers, including the `404` and the `500`
(`conformance/cases/cors/c-cors-0033`), because a browser withholds an undecorated response from
the page entirely and the status the operator is looking at becomes invisible to the client.

## What is not here

- **The website endpoint and the console.** A second protocol face with its own cross-origin
  needs is not this family's, and no operation outside the S3 data plane participates in
  bucket-level CORS.
- **Enforcement of anything.** CORS is a browser mechanism. A preflight allowance says what a
  browser may send; it says nothing about who may do it.
