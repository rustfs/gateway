# ADR-0053: The caller's secret only over a signed body

- Status: Accepted
- Date: 2026-11-11
- Trigger: handing RustFS's STS endpoint the caller's secret (rustfs/gateway#1587) would honour a replayed head with a rewritten form body
- Supersedes / Superseded by: none

## Context

ADR-0022 and ADR-0024 let an operation opt in to the caller's secret. The secret reaches the
handler when the operation's spec opts in and the authenticator was told to hand it over. Until
now the opted-in operations were the 49 RustFS admin rows whose body is sealed with that secret.
An attacker without the secret cannot forge such a body.

`rustfs:StsFormPost` needs the secret for another reason. RustFS's `AssumeRole` compares the
secret that authenticated the request with a fresh IAM lookup. Its form body carries every
parameter that comparison authorises: `DurationSeconds`, `Policy` and `RoleArn`.

An authenticated request does not always have a signed body. Header SigV4 with
`UNSIGNED-PAYLOAD` signs the head only, a presigned URL signs no body, and SigV2 signs no body.
With the secret handed over unconditionally, a captured head could be replayed inside the skew
window with a rewritten body, and the handler's comparison would pass.

RustFS itself refuses only SigV2, SigV2-presigned and POST-policy authentication on this route.
It accepts a SigV4 `UNSIGNED-PAYLOAD` `AssumeRole`.

## Decision

`OperationSpec::hand_caller_secret_to_handler_over_a_signed_body()` is a second form of the
per-operation opt-in. It sets the existing opt-in and adds one condition: the secret reaches the
handler only when a SigV4 header signature covers the body the handler is handed. "Covers" has
exactly three forms:

- a declared `x-amz-content-sha256` digest, which the facade compares with every body it reads;
- the STS body digest the authenticator computes itself when no payload header is sent;
- an aws-chunked chain of chunk signatures.

`Authentication::signs_its_body` answers this from the authenticator's own state. The facade
drops the secret, zeroized, on the line that already applies the opt-in (`CallerKeyOptIn::admits`).
The condition also holds when the deployment hands the secret to every operation.

Admission is unchanged. An unsigned-body request still reaches the handler, without the secret,
so RustFS's comparison fails closed as it did before the opt-in. The 49 sealed rows keep the
unconditional opt-in. The generator renders the new form for every form-claimed operation it
opts in (`admin::spec_over_a_signed_body`).

## Evidence

- RustFS's `AssumeRole` compares a fresh lookup's secret with the authenticating one:
  https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/handlers/sts.rs
  (the branch refuses unless both secrets are equal in constant time).
- RustFS's `reject_unbound_custom_route_auth` refuses SigV2, SigV2-presigned and POST-policy
  authentication on custom routes, and nothing else:
  https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/router.rs
  (it leaves SigV4 `UNSIGNED-PAYLOAD` and presigned SigV4 admitted).
- Measured through an assembled RustFS-profile service in
  `crates/goldens/src/operation_diff/sts_parity/secret.rs`:
  - the secret reaches the handler for header SigV4 `sts` without a payload header, `sts` with a
    declared digest, and `s3` with a declared digest;
  - it does not reach the handler for `UNSIGNED-PAYLOAD` under `s3` or `sts`, presigned SigV4 Web
    Identity under either service, or SigV2;
  - each case was mutated once (rustfs/gateway#1587).

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Edit the inventory row to claim a sealed body | The inventory records RustFS's body sealing; the STS route seals nothing, and a refresh would overwrite the edit |
| Refuse unsigned-body `AssumeRole` in the codec | It changes ADR-0044's admission, needs a new codec-visible fact, and still hands the secret to unsigned-body Web Identity and unknown actions |
| Require a signed body for every opted-in operation | It narrows the 49 sealed rows, whose body the secret already protects, and could break an admin client that sends `UNSIGNED-PAYLOAD` |
| Read `x-amz-content-sha256` in the codec | Stage filters may rewrite the headers a codec sees; the STS body digest the authenticator computes is invisible there |

## Consequences

- The gateway is stricter than RustFS for a SigV4 `UNSIGNED-PAYLOAD` or presigned `AssumeRole`.
  RustFS mints a session; the gateway's handler holds no secret, so RustFS's comparison refuses.
- Every new form-claimed opt-in gets the signed-body condition by default.
- A custom authenticator that does not use the built-in body-digest path gets the secret over a
  signed body only through a declared digest or a chunk chain.
