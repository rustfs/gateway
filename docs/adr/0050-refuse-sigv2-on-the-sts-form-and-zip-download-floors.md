# ADR-0050: Refuse SigV2 on the STS form and zip download floors

- Status: Accepted
- Date: 2026-11-11
- Trigger: a RustFS-profile security difference (rustfs/gateway#1592), refining ADR-0044's STS action credentials and ADR-0042's zip-download bearer floor
- Supersedes / Superseded by: none

## Context

ADR-0044 gives the STS form endpoint, `rustfs:StsFormPost`, one shared floor:
`OperationFloor::builtin(NAME, SigService::Sts)` with anonymous access. Ordinary `AssumeRole`
must carry a verified header credential; Web Identity stays reachable without one, because its
token in the form body is its authentication.

That floor admitted SigV2. A SigV2 header `AssumeRole` was verified and reached the handler, and
so did a SigV2-presigned Web Identity form under the RustFS profile, which enables SigV2
presigned URLs and admits presigned URLs on every standard operation. The goldens pinned both as
positives (`sts_parity::sec1::sec1_14`, `sec1_15`).

SigV2 does not cover the request body, and covers only a fixed set of query sub-resources. Every
STS parameter travels in the form body. A SigV2 signature on this route therefore binds none of
what the operation acts on. RustFS refuses SigV2 here once credentials are presented.

The existing narrowing, `require_sigv4_under_every_policy` (ADR-0049), cannot be used. It also
refuses anonymous requests, which would remove unsigned Web Identity.

The zip download (`admin::zip_token_floor`, ADR-0042) had the same gap in another form. A SigV2
header without a token passed the floor. It was refused later, by the bearer check or by RustFS's
handler, rather than at the floor. The SigV4 requirement cannot be used there either: it refuses
every bearer token, and the registry refuses that combination.

## Decision

### The rule

`OperationFloor::refuse_sigv2_under_every_policy` refuses every SigV2 request, under every
`SigV2Policy`:

- a header signature;
- a presigned URL;
- a POST policy.

The refusal is `AccessDenied` at the floor's allow-list step (H3). It comes before the SigV2
credential is parsed and before any credential lookup. A known and an unknown access key get the
same answer, and so do a correct and a forged signature. It is the answer the SigV4 requirement
gives a SigV2 request, so a caller cannot tell which of the two rules refused it.

The rule changes nothing else. A SigV4 header signature, presigned URL or POST policy is admitted
as the allow-list and the floor policies already say. So is a request that presents no AWS
credential: an anonymous request, a query bearer token, or a registered custom scheme.

`OperationFloor::refuses_sigv2_under_every_policy` is the one predicate the floor reads. It is
true when the operation called the new method or requires SigV4 under every policy. The SigV4
requirement implies the refusal, so the two cannot disagree.

### Where it applies

- `rustfs:StsFormPost`: `builtin(Sts)`, anonymous allowed, SigV2 refused. The generator template
  (`xtask/src/rustfs_admin_dialect/form.rs`) owns it.
- `admin::zip_token_floor`: the privileged admin floor, SigV2 refused, plus the bearer claim. A
  SigV2 header is now refused at the floor, with or without a token, and with or without an
  installed bearer verifier. The verifier is never asked about it.

### How it composes

| Combined with | Decision | Why |
| --- | --- | --- |
| `require_sigv4_under_every_policy` | Allowed, not refused at registration | Both rules only narrow, and the stronger one stands in either order. Neither admits anything the other refuses, so the floor is redundant, not contradictory. The registry refuses contradictions only. |
| A query bearer claim | Allowed | The bearer path reads only requests with no AWS credential marker, so it never sees SigV2. The registry still refuses the SigV4 requirement beside a bearer claim, also when this rule is declared as well. |
| A custom-scheme registry | Unaffected | A custom scheme is only offered requests with no AWS marker, so a SigV2 request never reaches one. The operation's allow-list decides custom-scheme requests as before. |

### Known differences from legacy RustFS

Both fail closed:

- **Forged SigV2 header.** Legacy verifies the signature before its router's SigV2 check, so it
  answers `SignatureDoesNotMatch`. The gateway answers `AccessDenied`, because it refuses before
  resolving any credential.
- **SigV2 header plus a zip token.** Legacy returns from its access check on a token-carrying zip
  path before its SigV2 refusal, and lets the handler judge the token. The gateway refuses the
  SigV2 header at the floor. The minted token-only URL and the SigV4-signed download are unchanged.

ADR-0044's claimed-route SigV2 canonical resource still applies to any form-claimed operation
without this rule. On the STS route it is no longer reachable. `sec1_16` and `sec1_17` now pin the
floor's refusal instead.

ADR-0044 and ADR-0042 are not edited. This record narrows their floors.

## Evidence

- RustFS's router refuses a SigV2 `Authorization` header, a `Signature` query key and a
  credentialed multipart POST on its custom routes. Its comment gives the reason: SigV2 binds
  neither the route's query arguments nor its payload.
  https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/router.rs#L3391-L3421.
  Read from source.
- RustFS's access check lets an unsigned STS form and a token-carrying zip path through before
  that refusal, and applies it to every other request that reaches the credential check:
  https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/router.rs#L3560-L3620.
  Read from source.
- RustFS's own test sends both SigV2 forms to a list of custom routes that includes the
  `/?Action=AssumeRole` query, and expects `AccessDenied` for each:
  https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/admin/router.rs#L6226.
  Read from source.
- Measured before the implementation:
  - the new sig floor tests did not compile against the missing API;
  - with the tests in place and the floors unchanged, 13 of 39 STS-parity and zip goldens failed.
    Every failure was a SigV2 row.
- Measured after: the same 39 pass, and so do the sig, core registry, dialect and xtask suites.
- Measured mutation audit, run locally: each new or changed assertion went red under a labelled
  mutation. The mutations covered:
  - the floor ignoring the rule;
  - the predicate losing the SigV4 implication;
  - the setter over-reaching into the SigV4 requirement;
  - the refusal moved after the credential parse;
  - each dialect floor without the rule;
  - the legacy stand-in admitting SigV2;
  - a deaf credential recorder;
  - a no-op unknown-key rewrite;
  - both registry directions.

  The table is in rustfs/gateway#1592's pull request.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| `require_sigv4_under_every_policy` on the STS form | Refuses unsigned Web Identity, whose token is its authentication (ADR-0044). |
| Make the STS floor privileged | Changes Web Identity's independent contract. ADR-0044 already rejected it. |
| Refuse SigV2 in the STS codec, after verification | The credential lookup has already happened. Known and unknown keys could then be told apart, and the handler path would still hold a SigV2-verified identity until the codec runs. |
| Turn SigV2 off for the whole RustFS profile | Breaks legacy clients on every ordinary S3 operation, where RustFS still accepts SigV2. |
| Refuse the SigV2 refusal beside the SigV4 requirement at registration | Nothing contradicts. It would only stop floor helpers from being layered, as `admin::floor` and `zip_token_floor` are. |
| Leave the zip download as it was | The later refusal works, but it lets SigV2 reach credential lookup and, with a verifier installed, the bearer check. The rule composes with the claim, so there is no reason to keep the gap. |

## Consequences

- `refuse_sigv2_under_every_policy` and `refuses_sigv2_under_every_policy` become part of
  `rustfs-gateway-sig`'s public surface.
- The floor's SigV2 refusal now reads the new predicate. Every operation that requires SigV4
  behaves exactly as before.
- A deployment that sent SigV2 `AssumeRole` or SigV2-presigned Web Identity through the gateway
  must switch to SigV4, as it would have to against RustFS itself.
- A future operation whose parameters SigV2 does not cover, and which must stay reachable
  without a signature, takes this rule rather than a new one.
- These tests pin the decision:
  - `crates/sig/tests/sigv2_refused_floor.rs`;
  - the operation unit tests;
  - the core registry floor tests;
  - the dialect floor declarations;
  - the goldens' `sts_parity::sigv2`, `sts_parity::sec1` and `rustfs_admin_dialect::zip_sigv2_tests`.
