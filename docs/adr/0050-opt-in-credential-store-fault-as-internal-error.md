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
default. Under it, and only for a lookup that returned `Err(ProviderError)`, the authenticator
returns `Unavailable` instead of the closed refusal. It does so at the point an unknown key is
answered: after the placeholder derivation and the comparison on the SigV4 and SigV2 paths, and at
the early lookup refusal of the RustFS STS body signature, where an unknown key is answered too. It
does not return earlier. `CredentialLookup::NotFound`, session and disabled-credential refusals,
signature mismatches and every other credential failure keep their answers. The `500` body is the
service's constant sentence and carries no request text, access key or provider detail. One switch
covers every form the authenticator serves: SigV4 header, presigned, streaming and POST policy
(routed, and the RustFS-profile object-path refusal), SigV2 header, presigned and POST policy, and
the STS body signature. `SigV4Authenticator::rustfs_profile` turns it on. The authenticator's
`Debug` names it (`answers_credential_store_faults_as_unavailable`); no posture line is added,
because no authenticator switch is on one.

## Evidence

- AWS: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html (the old
  `ErrorResponses.html` address now redirects to the API reference's welcome page). In our words:
  the S3 error table lists `InternalError` as a `500` server-side failure the client should retry,
  and keeps `InvalidAccessKeyId`, a `403`, for an access key ID that is not on record.
- RustFS: the `check_key` error path in `rustfs/src/auth.rs` (RustFS 1.0.5), as recorded in
  rustfs/gateway#1585.
- Measured: `crates/gateway/tests/store_fault_answer.rs` drives ten authentication forms through an
  assembled service in both switch positions, with a backend error, an unavailable store and a
  provider panic. Mutation results are listed in the pull request that lands this ADR.

## Rejected alternatives

- **Answer `500` by default.** The default is AWS's documented closed answer and the one every
  existing deployment's clients see; changing it is a wire change for hosts that did not ask.
- **Answer the fault as soon as the lookup returns.** It would give a fault a latency class of its
  own, shorter than a wrong signature's. The switch changes only the answer, not the work done
  before it.
- **A distinct `503 ServiceUnavailable`.** RustFS answers `500 InternalError`, and `Unavailable` is
  already rendered as that by the service; a second status would be a second migration difference.

## Consequences

- A store-wide outage reveals nothing about any key: every key answers `500`. A fault confined to
  one stored record — one unreadable entry, or one the provider reports as a fault, such as an
  empty secret converted with `ProviderError::from` — answers `500` for that key and `403` for an
  unknown one, so a caller can tell "this key exists and its record is unreadable" from "this key is
  not on record". That is why the switch is opt-in, and a host that enables it accepts the
  distinction.
- A fault is still counted, never cached, and never an anonymous request.
- Enforcement: `store_fault_answer.rs` (both positions, every form, the order), the preset's unit
  suite pinning the switch in `SigV4Authenticator::rustfs_profile`, and the difftest seam guard that
  requires every preset switch on the seam stack.
