# ADR-0023: An opt-in any-region signing scope for RustFS clients

- Status: Accepted
- Date: 2026-09-14
- Trigger: crate boundary: `rustfs-gateway-sig` gains a second scope-region policy that `rustfs-gateway` exposes on its authenticator
- Supersedes / Superseded by: none

## Context

`enforce_scope` admits a SigV4 credential scope only when its region is in the deployment's
`RegionSet`. Otherwise it answers `400 AuthorizationHeaderMalformed` and names the region to use
(ADR-0009, `c-bkt-0030`). That is what AWS does, and it stays the default.

RustFS today accepts any scope region. Its s3s service only checks the region when
`S3Config::expected_region` is set, and RustFS never sets it. RustFS clients rely on this: tools
default to `us-east-1`, and operators commonly configure an arbitrary label such as `rustfs` or
`local`. The GetBucketLocation differential of rustfs/backlog#1752 (rd-loc-0004) showed the gap.
Switching a RustFS deployment to the gateway would turn every such client's request into a 400.

The region is not a secret and not an authority. It is one input to the signing-key derivation
(`HMAC(HMAC(HMAC(secret, date), region), service)`). A signature therefore stays bound to the
region the client named, whichever region the server accepts. The region check exists for two
things: to route a client to the right endpoint in a multi-region service, and to refuse a
signature minted for another region of the same account, which AWS scopes separately.
A RustFS deployment has one endpoint and no per-region credentials, so neither applies to it.

## Decision

`ExpectedScope` gains an opt-in policy. `ExpectedScope::accepting_any_region()` admits every
presented region that satisfies the same grammar `RegionSet::new` enforces on configured names:
1..=64 bytes of lowercase ASCII letters, digits or `-`. A region outside that grammar is still
refused as a scope mismatch that names the first configured region. The date and service checks
are unchanged, and so is the derivation: the key is still derived from the presented region, so
only the checked scope is ever used.

`SigV4Authenticator::accept_any_signing_region()` turns the policy on for header, presigned and
POST-policy SigV4 alike. It is off by default. The authenticator's `Debug` names the policy
(`accepts_any_signing_region`); the start-up posture report has no region line today, and this
decision does not add one. The `RegionSet` stays required and keeps its two other uses: it is the
region named in a rejection, and the region `GetBucketLocation` compares against.

This is the RustFS profile of rd-loc-0004. It is opt-in, and a RustFS ring-2 adapter is expected to
enable it. An AWS-compatible deployment never does.

## Evidence

- s3s `9c4690d8` and `f3e17541`: `validate_sig_v4_region` runs only when `expected_region` is
  `Some`, and the default configuration leaves it `None` (`ops/signature.rs`, `config.rs`).
- RustFS main (`rustfs/rustfs@64e0ac08`) never sets `expected_region`, so it verifies a signature
  for any scope region.
- Measured: the goldens pin `rd-loc-0004` drives both stacks with a request signed for a region
  the gateway does not serve. s3s admits it; the gateway answers 400 by default and admits it with
  the profile.
- Security: the profile changes no key material and no comparison. `c-sig-0342` and `c-bkt-0030`
  still hold for the default. The profile tests pin that a region outside the grammar is still
  refused, and that the date and the service are still enforced.
- Mutation results are listed in the pull request that lands this ADR.

## Rejected alternatives

- **Align every deployment with RustFS.** It drops the AWS endpoint-routing answer
  (`AuthorizationHeaderMalformed` with `<Region>`) for every deployment that has more than one
  region. The default stays AWS.
- **Accept any `ascii_graphic` region, as the scope parser does.** Legacy accepts that too, but a
  region outside the configured-name grammar cannot become an s3s `Region`, so the migration seam
  would refuse it by name after authentication. Refusing it at the scope is earlier and names the
  correct region.
- **List the clients' regions in the `RegionSet`.** An operator cannot know the labels every
  client uses, and a wrong guess shows up as a 400 in production.
- **Put the flag on `RegionSet`.** The set is also used by `GetBucketLocation` and as the region a
  rejection names. A set that "contains everything" would change both.

## Consequences

- A deployment that enables the profile no longer tells a misconfigured client which region to
  use. Its clients get the signature's own verdict instead.
- A signature minted for another deployment with the same credential and a different region
  label now verifies here. This is already true of RustFS today, and credential isolation between
  deployments is the operator's responsibility, not the region's.
- `VerifiedScope::region()` can now be a region the deployment does not list. Handlers that read
  it (the RustFS adapter passes it to `s3s::S3Request::region`) see the client's region, exactly
  as legacy RustFS handlers do.
