# ADR-0050: An opt-in internal error for a credential-store fault

- Status: Accepted
- Date: 2026-11-11
- Trigger: a RustFS-profile wire difference in degraded operation (rustfs/gateway#1585, ledger entry R-068 of rustfs/backlog#2684)
- Supersedes / Superseded by: none

## Context

`SigV4Authenticator` reads a credential through `GuardedCredentialProvider`, which turns a backend
error, an unavailable store, its own hard timeout and an isolated provider panic into
`ProviderError`. The authenticator has answered every such fault exactly as it answers an unknown
access key: it derives from `timing::placeholder_secret`, completes the comparison, and refuses with
`403 InvalidAccessKeyId`. The guard counts the fault for operators; the client is told its key does
not exist.

RustFS 1.0.5 answers a failed credential-store read for one key with `500 InternalError`
(`rustfs/src/auth.rs`, the `check_key` error path through `iam_lookup_error_to_s3_error`). SDKs
retry a `500` with backoff and recover once the store does; they treat `InvalidAccessKeyId` as
terminal. A host moving from RustFS's own front end to the gateway therefore turns a storage
brown-out into hard failures for clients holding valid credentials, and the answer they get is
untrue.

`Authenticator::authenticate` already has a third outcome, `Err(Unavailable)`, which the service
renders as `500 InternalError` with a constant sentence. The built-in authenticator never produced
it.

## Decision

`SigV4Authenticator::answer_credential_store_faults_as_unavailable()` is an opt-in switch, off by
default. Under it, and only for a lookup that returned `Err(ProviderError)` — a backend error, an
unavailable store, the guard's timeout or an isolated provider panic — the authenticator returns
`Unavailable` instead of the closed refusal. `CredentialLookup::NotFound`, session and
disabled-credential refusals, signature mismatches and every other credential failure keep their
answers, and a request refused before the lookup (its scope, date or region) keeps its own refusal.
The `500` carries the service's constant sentence and no request text, access key or provider
detail, and it hands the transport the connection verdict of an authentication failure: `Close`
while body octets are still owed, because the peer was never identified
(`close::after_unavailable`). That verdict applies to every authenticator's `Unavailable`, a custom
one's included.

The answer is given where an unknown key is answered, never earlier. On the SigV4 and SigV2 paths
that is after the placeholder derivation and the comparison. One switch covers every form the
authenticator serves: SigV4 header, presigned, streaming and POST policy (routed, and the
RustFS-profile object-path refusal), SigV2 header, presigned and POST policy, and the early path
below. `SigV4Authenticator::rustfs_profile` turns it on. The authenticator's `Debug` names it
(`answers_credential_store_faults_as_unavailable`); no posture line is added, because no
authenticator switch is on one.

**Stated deviation: the early lookup refusal of `accept_legacy_rustfs_signing_services`.** The
issue's constraint is that a fault must not answer earlier than a wrong signature does. One path
breaks it. With `accept_legacy_rustfs_signing_services` on, any header-signed request whose credential
scope names `sts` and which omits `x-amz-content-sha256` — on any route, not only an STS one —
takes the STS body-digest path. There an unknown key is refused before the body is read and before
any derivation or comparison, so that the body is never read for a key that is not on record
(rustfs/gateway#1230). A fault is answered at that same point. A fault and an unknown key therefore
share one latency class on that path, and both answer faster than a wrong signature over a found
key, which reads the body and compares. Under the RustFS profile the path is client-selectable: a
caller chooses it by naming `sts` in its scope. This adds no oracle the status code does not
already give, and an unknown key already took this path. Making a fault slower than an unknown key
there would separate the two by latency instead.

## Evidence

- AWS: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html (the old
  `ErrorResponses.html` address now redirects to the API reference's welcome page). In our words:
  the S3 error table lists `InternalError` as a `500` server-side failure the client should retry,
  and keeps `InvalidAccessKeyId`, a `403`, for an access key ID that is not on record.
- RustFS: the `check_key` error path in `rustfs/src/auth.rs` (RustFS 1.0.5), as recorded in
  rustfs/gateway#1585.
- Measured: `crates/gateway/tests/store_fault_answer.rs` drives ten authentication forms through an
  assembled service in both switch positions, with a backend error, an unavailable store, a
  provider panic and a guard timeout. Mutation results are listed in the pull request that lands
  this ADR.

## Rejected alternatives

- **Answer `500` by default.** The default is AWS's documented closed answer and the one every
  existing deployment's clients see; changing it is a wire change for hosts that did not ask.
- **Answer the fault as soon as the lookup returns.** It would give a fault a latency class of its
  own, shorter than a wrong signature's. The switch changes only the answer, not the work done
  before it.
- **A distinct `503 ServiceUnavailable`.** RustFS answers `500 InternalError`, and `Unavailable` is
  already rendered as that by the service; a second status would be a second migration difference.

## Consequences

What the per-key `500` reveals, stated plainly. It is why the switch is opt-in, and a host that
enables it accepts these:

- **Ordinary keys:** nothing new. `SignatureDoesNotMatch` versus `InvalidAccessKeyId` already tells
  a found key from an unknown one.
- **Hidden records:** a disabled or expired credential, and a session credential presented without
  its token, are deliberately answered byte-identically to an unknown key (GHSA-3p3x-734c-h5vx). A
  fault confined to such a record — one unreadable entry, or one the provider reports as a fault,
  such as an empty secret converted with `ProviderError::from` — answers `500` and reveals that the
  record exists. That defeats exactly the hiding those cases otherwise get.
- **A slow store:** the guard turns slowness into a fault at its deadline (one second by default).
  A store that is slower for existing records than for misses becomes a status-code existence
  oracle during a brown-out: `500` for existing keys, `403` for unknown ones.
- **The negative cache during a full outage:** a key the store reported missing in the last 30–60
  seconds is answered from the cache as an unknown key, `403`, while every uncached key answers
  `500`. So "a store-wide outage reveals nothing" is not exactly true: it reveals that a missing
  key was probed within the cache's lifetime.
- **A provider that reports some unknown keys as faults** instead of `NotFound` distinguishes those
  keys from other unknown ones.

Availability:

- A retryable `500` makes SDKs retry against a store that is already failing. Faults are never
  cached and nothing breaks the circuit, so each retry is a fresh backend call of up to the guard's
  deadline. The only bound is the governor's pre-lookup `CredentialLookup` class, which charges
  before the lookup whatever its outcome. Before this switch the same fault gave a terminal `403`.
  The only client-driven route to another caller's `500` is making the backend exceed its deadline,
  and for that caller a retryable `500` is arguably better than a terminal `403`.

Unchanged:

- A fault is still counted, never cached, and never an anonymous request.

Enforcement:

- `store_fault_answer.rs` and its `edges` module: both positions, every form, status, headers,
  connection verdict and body, and the order. The preset's unit suite and an end-to-end fault through
  `SigV4Authenticator::rustfs_profile`. The difftest seam guard requires every preset switch on the
  seam stack.
