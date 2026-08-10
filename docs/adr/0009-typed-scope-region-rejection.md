# ADR-0009: Typed scope-region rejection across sig and gateway

- Status: Accepted
- Date: 2026-08-11
- Trigger: axioms A2 and A3 (untrusted scope text cannot become response detail, and the authentication-to-resolution transition is fixed by types)
- Supersedes / Superseded by: none

## Context

`enforce_scope` currently returns the fieldless `AuthError::AuthorizationHeaderMalformed` for a
date, region or service disagreement. That is safe for authentication, but it erases the trusted
expected region before the gateway can satisfy ADR-0008. The resulting conflict is observable:
rustfs/backlog#1706 requires a signing-region mismatch to be `400 AuthorizationHeaderMalformed`
with exactly one bounded `Region` detail, and `c-bkt-0030` already fixes the same wire response.

The gateway cannot reconstruct that fact. The presented region is attacker-controlled, a default
region can be false for a multi-region deployment, and the `Authenticator` trait returns only a
`Verdict`. Making the service guess would turn a validated fact into a convention. Reusing the
fieldless error would either omit ADR-0008's required detail or force the ordinary error builder to
accept a contextual code, reopening the second-authority path that ADR-0008 closed.

This path is also a secret boundary. A rejection may carry the deployment's bounded remediation
region, but never the presented region, credential, signature, expected signature, signing key,
canonical request or comparison result.

## Decision

The sig crate introduces the following exact public surface:

```rust,ignore
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScopeRegion(Box<str>);

impl ScopeRegion {
    pub const MAX_LEN: usize = 64;
    pub fn as_str(&self) -> &str;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRejection(Option<ScopeRegion>);

impl ScopeRejection {
    pub fn expected_region(&self) -> Option<&ScopeRegion>;
}

pub fn enforce_scope(
    presented: &CredentialScope,
    clock: ClockChecked,
    expected: &ExpectedScope<'_>,
) -> Result<VerifiedScope, ScopeRejection>;

pub struct AuthenticationOutcome {
    verdict: Verdict,
    scope_rejection: Option<ScopeRejection>,
}

impl AuthenticationOutcome {
    pub fn ordinary(verdict: Verdict) -> Self;
    pub fn verdict(&self) -> &Verdict;
}

pub trait Authenticator: Send + Sync + 'static {
    fn authenticate<'a>(
        &'a self,
        request: &'a Authentication<'a>,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>>;
}

impl ErrorContext {
    pub fn authorization_scope_malformed() -> Self;
}
```

`ScopeRegion` has no public constructor. `RegionSet::new` remains the sole public input and now
validates every configured name as 1..=64 bytes of lowercase ASCII letters, digits or `-`, the
same predicate as core's `RegionLabel`. It stores those values as `ScopeRegion`, sorts them
byte-lexicographically and removes duplicates. A non-empty `RegionSet` therefore always has one
stable remediation region: its canonical first entry, independent of whether the caller supplied
a `Vec`, array, set or another `IntoIterator`. `contains` and `names` retain their signatures and
byte-exact membership behaviour; `names` now exposes canonical order.

`ScopeRejection` is exactly a private `Option<ScopeRegion>` and has no `Default`, public constructor
or mutable accessor. There is no public mismatch-kind enum because no downstream consumer needs to
distinguish date from service. `enforce_scope` is its only producer. A region disagreement carries
a clone of the configured set's first `ScopeRegion`; date and service disagreements carry `None`.
The presented region is never retained. The terminator and syntactic failures remain parser errors
and never construct a `ScopeRejection`.

`Verdict`, `Verdict::reject(AuthError)`, `Verdict::rejection() -> Option<AuthError>`, and every
public `AuthError` variant and method remain unchanged. `AuthError` stays fieldless-or-closed and
`Copy`; no region or secret is added to it.

The gateway changes `Authenticator::authenticate` to return `AuthenticationOutcome` instead of a
bare `Verdict`. Its fields are private, it has no `Default` or public contextual constructor, and
`ordinary` is the only public constructor. `ordinary` always stores `scope_rejection: None`; its
argument remains the existing receipt-bearing `Verdict`, so it does not weaken authentication.
The built-in `SigV4Authenticator`, which lives in the same facade crate as the carrier, alone calls
a crate-private `AuthenticationOutcome::scope_rejected(ScopeRejection)`. That constructor always
stores the supplied scope proof beside the fixed
`Verdict::reject(AuthError::AuthorizationHeaderMalformed)`; it accepts no replacement verdict or
error. A direct sig caller can obtain `ScopeRejection` only by running `enforce_scope`, but cannot
attach it to the facade carrier; a custom `Authenticator` can always reject through
`ordinary(Verdict::reject(...))`, and cannot mint a trusted region detail.

`AuthenticationOutcome::verdict()` borrows the exact verdict stored by either constructor. It
does not consume, clone, rewrite or supplement it, and it never exposes the private scope proof.
Audit and observer consumers therefore continue to classify a built-in scope rejection as
`AuthorizationHeaderMalformed`. The service uses a private consuming split only after observation
has finished.

The built-in `SigV4Authenticator` converts `enforce_scope`'s error only with the crate-private
`scope_rejected` constructor. The service consumes the carrier privately. When
`expected_region()` is present, it performs the checked conversion to
core `RegionLabel` and calls `ErrorContext::authorization_region_mismatch`; conversion failure is
a static `InternalError` and never echoes the refused text. When it is absent, the gateway calls
the new closed `ErrorContext::authorization_scope_malformed()`, which resolves to `400
AuthorizationHeaderMalformed` with no headers or details. Both constructors choose the same
static message internally. ADR-0008's ordinary `HandlerError` payload continues to reject the
contextual `ErrorCode::AuthorizationHeaderMalformed`; this does not restrict
`AuthenticationOutcome::ordinary`, which accepts every existing `Verdict`. The service maps an
ordinary `AuthError::AuthorizationHeaderMalformed` from a custom authenticator to the same closed
`authorization_scope_malformed()` context: status `400`, the canonical static message and no
detail. It cannot forge the region-bearing context.

The consumer matrix is closed:

| Producer | Public construction available | Service interpretation |
|---|---|---|
| built-in `SigV4Authenticator` after `enforce_scope` | crate-private contextual carrier | region context when present; closed no-detail scope context otherwise |
| custom `Authenticator` | `AuthenticationOutcome::ordinary(Verdict)` only | `AuthorizationHeaderMalformed` may use the closed no-detail context; no contextual region authority |
| direct sig caller | read-only `ScopeRejection` returned by `enforce_scope` | cannot enter the gateway carrier |
| gateway service | no constructor; private field consumption only | consumes once before ordinary `Verdict::rejection` handling |

Header and presigned SigV4 use the same `Presented`, `ExpectedScope`, `enforce_scope` and verdict
transition. Neither path gets a separate region constructor. The implementation adds wire parity
for both forms: a wrong region resolves to status `400`, code `AuthorizationHeaderMalformed`, and
one `Region` detail containing the canonical configured region.

## Evidence

**Measured:** on `origin/main` at `19aed9352d1850a2dd9c551117cb8c23e5942f68`, the one scope
function returns `AuthError` and all three comparisons collapse to the same fieldless variant:

```text
$ rg -n 'Result<VerifiedScope, AuthError>|Err\(AuthError::AuthorizationHeaderMalformed\)' crates/sig/src/scope.rs
153:) -> Result<VerifiedScope, AuthError> {
155:        return Err(AuthError::AuthorizationHeaderMalformed);
158:        return Err(AuthError::AuthorizationHeaderMalformed);
161:        return Err(AuthError::AuthorizationHeaderMalformed);
```

**Measured:** the built-in authenticator is the only non-test caller, and it immediately converts
the erased error into a fieldless verdict:

```text
$ rg -n 'enforce_scope\(' crates --glob '*.rs' --glob '!**/*tests.rs'
crates/gateway/src/ext/authenticator.rs:402:        let verified = enforce_scope(presented.scope(), sealed.clock(), &expected)?;
crates/sig/src/scope.rs:149:pub fn enforce_scope(
```

**Measured:** `RegionSet` and the presented `CredentialScope` currently accept any ASCII-graphic
region, while core's renderable `RegionLabel` accepts only lowercase ASCII letters, digits and
hyphens. A direct conversion is therefore not infallible until the configuration predicate is
aligned:

```text
$ rg -n 'is_ascii_graphic|is_ascii_lowercase' crates/sig/src/scope.rs crates/sig/src/parse.rs crates/core/src/fault.rs
crates/sig/src/scope.rs:68:                && region.bytes().all(|byte| byte.is_ascii_graphic())
crates/sig/src/parse.rs:213:        if region.is_empty() || region.len() > Self::MAX_REGION_LEN || !region.bytes().all(|b| b.is_ascii_graphic()) {
crates/core/src/fault.rs:96:                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
```

**Measured:** the existing wire case requires the fact that the erased value cannot currently
supply:

```text
$ rg -n 'status = 400|code = "AuthorizationHeaderMalformed"' conformance/cases/bkt/c-bkt-0030.toml
41:status = 400
43:code = "AuthorizationHeaderMalformed"
```

**[inferred]:** sorting the already bounded configured set makes one remediation region stable for
both ordered and unordered inputs without adding ambient configuration or trusting request text.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Render the presented region | It is attacker-controlled and tells the client to repeat the value that was just rejected |
| Read a default region in the service | The authenticator's `RegionSet` is the authority; a second value can disagree and is false for multi-region deployments |
| Put `String` or `Cow<str>` on `AuthError` | It accepts unbounded or request-derived text, removes `Copy`, and makes every authentication log site a potential secret/reflection sink |
| Add `AuthError::WrongRegion(ScopeRegion)` or `Verdict::reject_scope` | It lets any custom authenticator mint the contextual region response; the gateway-private carrier confines that authority to the built-in verifier |
| Use the caller's iterator first item | `HashSet` and similar inputs have unstable order, so identical configuration could emit different remediation regions |
| Let the fieldless authentication rejection enter the ordinary `HandlerError` payload | Reopening ordinary contextual-code construction creates a second response authority; the service must translate that verdict through the dedicated no-argument context |
| Make core depend on sig's rejection type | It reverses the existing `gateway -> core -> sig` dependency direction and creates a protocol-kernel cycle |
| Return all configured regions | ADR-0008 requires one `Region` detail, and exposing the full deployment set reveals more topology than the client needs to retry |

## Consequences

- The implementation is `BREAKING` for direct callers of `enforce_scope` because its error type
  changes. `rustfs-gateway-sig` receives its next minor version; core and the facade also receive
  their next minor versions for `authorization_scope_malformed` and the authenticator carrier,
  and workspace dependency declarations move with the ADR-0008 implementation. Direct scope-call
  migration is `AuthError` match/`map_err` code -> inspect `ScopeRejection::expected_region`.
- Custom `Authenticator` implementations change `Ok(verdict)` to
  `Ok(AuthenticationOutcome::ordinary(verdict))`. Direct consumers that previously received an
  owned `Verdict` keep the `AuthenticationOutcome` alive and inspect
  `outcome.verdict(): &Verdict`; there is no public consuming accessor that could silently discard
  the private scope proof. They keep using `Verdict::reject(AuthError)` and cannot mint a trusted
  region mismatch. Their explicit `AuthorizationHeaderMalformed` still resolves to the closed
  no-detail `400` form.
- Tightening `RegionSet::new` rejects uppercase or punctuated configured regions at startup. This
  is intentional: such a value cannot enter ADR-0008's XML-safe `RegionLabel`. The PR migration
  text names the lowercase letters/digits/hyphen rule. Tests build the same region set from
  opposite orders and an unordered iterator and require the same canonical remediation region.
- A deterministic guard pins the private `ScopeRejection` and `AuthenticationOutcome`
  representations, the sole contextual producer/consumer pair, the retained `AuthError`
  compatibility surface, canonical region sorting, and the absence of arbitrary text or
  secret-bearing fields. Compile-fail cases independently prove that external code cannot
  construct/destructure `ScopeRejection`, set carrier fields or call `scope_rejected`.
- Mutations remove or swap the configured expected region, copy the presented region, make the
  rejection or carrier constructor public, let `scope_rejected` accept or store a replacement
  verdict, make `verdict()` consume or expose the proof, route parser syntax through a scope
  context, swap the no-region and region contexts, let core `ordinary` accept the code, change
  status/code, add a detail to the no-region form or a second detail to the region form, change a
  custom authenticator's no-detail result, and break either header or presigned parity.
  `c-bkt-0030` must fail when the real wire transition is removed.
