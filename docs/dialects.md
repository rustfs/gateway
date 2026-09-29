# Dialects

A **dialect** is what a deployment adds to this gateway that AWS does not define: an admin API, an
STS surface, a vendor query key, a compatibility leniency. This document says what a dialect may
change, what it may never change, and the licence boundary that governs reproducing another
implementation's behaviour.

The mechanism lives in `crates/core/src/dialect/`. The worked example is
`crates/core/examples/dialect_overlay.rs`; every refusal below has a test in
`crates/core/tests/dialect.rs`.

## A dialect is an assembly unit, not a cargo feature

The arrangement this replaces is a cargo feature switching between two generated code trees. It
costs three things: the generated output doubles, two dialects cannot be enabled at once, and a
deployment that wants its own has to fork the framework.

A `Dialect` is a value instead. A deployment assembles as many as it needs and installs each one:

```rust
let router = RouterBuilder::new()
    .dialect(&acme)
    .dialect(&my_own)
    .handle_without_codec::<AcmeOperation, _>(backend)
    .build()?;
```

A conflict between two dialects — the same operation name, two rows at one precedence, an
undeclared overlap — is a start-up failure naming both sources, rather than whichever registration
the linker happened to see last.

## Three orthogonal dimensions

Compatibility with another implementation is not one thing. It is three, and they have different
mechanisms, different blast radii and different rules.

| # | Dimension | Mechanism | May | May not |
|---|---|---|---|---|
| 1 | **Extra operations** | `Dialect::operations`, `Dialect::claimed_operations`, this document | add a **new** `vendor:Name` operation with its own route row — or a reviewed path-prefix claim and rows inside it — spec, floor and handler | take an AWS operation name in any case; stand in front of a standard row without a declaration; claim a prefix that could shadow a bucket; change a standard operation's row, spec or authentication requirement |
| 2 | **Extension fields on existing types** | `ExtField` codec vtable | add a child element to an existing parent shape | change an existing field's type, order or name; add a field to a security-relevant type |
| 3 | **Parsing leniency** | runtime `CodecPolicy` | relax request-XML strictness — unknown elements, bare-literal bodies | relax anything about a security-relevant configuration, a signature, or an authorisation decision |

**Only dimension 1 exists today.** The `ExtField` feasibility spike and its ADR have now landed —
`docs/adr/ADR-0007-ext-field-codec.md`, evidenced by the `spikes/ext-field` crate — so dimensions 2
and 3 have an accepted conclusion, but they still have no production code. The ADR says so in
terms: the spike "does not authorize moving its implementation into production crates; that is a
separate task using this ADR as input." No workspace crate names `ExtField` or `CodecPolicy`, and
no generated codec carries an extension slot. So the rows for 2 and 3 remain the contract their
implementation has to satisfy rather than a description of code that exists.

One vendor exception does not wait for dimension 2. ADR-0033 makes six MinIO bucket-configuration
members (`ExpiryUpdatedAt`, `DelMarkerExpiration`, `ExpiredObjectAllVersions`, `DeleteReplication`,
`ExcludedPrefixes`, `ExcludeFolders`) ordinary model members that every assembly decodes and
re-encodes, because RustFS, the only product the gateway serves, reads them. `c-lifecycle-0018`
pins that on the wire and `crates/core/tests/lifecycle_roundtrip.rs` at the codec seam, together
with dimension 3's leniency: an unknown sibling is still accepted and dropped from the re-encoded
document. ADR-0007's persistence boundary still applies: `lenient` is not a lossless
read-modify-write policy, so production persistence must retain the original bytes and must never
turn a parse or registration miss into an absent configuration.

(ADR-0007's header says "Superseded by ADR-0010". ADR-0010 replaces one finding of it — Q6, the
handler request layout — and leaves the vtable decision standing; read the two together rather
than reading the header as retiring the dialect mechanism.)

The reason the split matters even while two thirds of it is pending: dimension 1 is the one that
touches routing and authorisation, which is where a mistake is a security incident rather than a
compatibility gap. Keeping it separate is what lets it land first.

## What a dialect operation must state

Six facts, each of them checked, and every one of them refused when it is missing or when the two
places it is written disagree.

| Fact | Where the code says it | Where the overlay says it |
|---|---|---|
| Name | `Operation::NAME` | `OverlayRow::name` |
| Precedence | `DialectRoute::precedence` or `ClaimedRoute::precedence` | `OverlayRow::precedence` |
| Selector | `DialectRoute::selector`, or every row of `ClaimedRoute::rows` | `OverlayRow::selector`, rendered — for a claimed route by `render_claimed_rows`, alias rows included |
| Action and resource | `OperationSpec::auth` | `OverlayRow::action`, `OverlayRow::resource` |
| Success status | `OperationSpec::success_status` | `OverlayRow::success_status` |
| Anonymous reachability | `OperationFloor::allows_anonymous` | `OverlayRow::anonymous` |

Plus evidence: `OverlayRow::evidence` is a non-empty list of URLs, and the sentence explaining each
one is written by whoever added the row. Never paste another project's prose — behavioural facts are
not copyrightable, the sentences describing them are (ADR-0001).

### Where the overlay lives

In the crate that owns the dialect, in one file, as `static` Rust data. `grep` for the vendor prefix
finds the entire surface a deployment added.

It is deliberately **not** under `model/overlays/`. That tree is the hand-written exception source
for the *pinned AWS model*: every entry names an operation or a shape the model defines, and codegen
fails on a name it does not have. A dialect operation is by definition not in the model.

It is deliberately **not** TOML. Every string the route table holds is `&'static` — the operation
name, the query keys inside a predicate, the spec's name — so a document parsed at start-up would
have to leak every string it read before it could reach the table. And ring 1 has no TOML reader:
the two in this workspace belong to build-time and test-time crates the protocol kernel must not
depend on, and a third reader on the start-up path would exist to check at run time what the
compiler already checks.

What a data format would have bought is that the record can disagree with the behaviour. That is
kept: the overlay is a second statement of the same six facts, and `DialectBuilder::build` refuses
the dialect when the two disagree. It is the same arrangement as `ShadowingDecl`, which is also
hand-written data checked against the table it describes.

## Registration refusals

All of these are start-up failures with a readable reason. The first four are
`crates/core/src/registry/reject.rs`'s and apply to every registration, dialect or not; the rest are
the dialect boundary's.

| Rule | Refused | Why |
|---|---|---|
| Un-namespaced name | `MyOp` | "Is this operation AWS's?" must be answerable from the name alone — the route table, the posture report and the audit log all do it |
| AWS name | `GetObject` | A dialect standing in front of an operation every client already calls |
| AWS name in another case | `getobject` | Two registry entries a human reads as one |
| No `AuthRequirement` | `auth: None` | The structural form of rustfs/rustfs#4845: a custom route that never reached the authorisation check because nothing said what permission it needed |
| Malformed action | `notanaction` | An action that is not `service:Action` cannot be matched by a policy |
| Duplicate name | two registrations | "The last registration wins" is how a plugin loaded later replaces a handler nobody expected it to touch |
| Wrong vendor | `other:Thing` in the `acme` dialect | Otherwise one dialect vouches for another's operations |
| An action in another vendor's namespace | `acme:Op` authorised as `other:Thing` | One dialect would answer questions in a namespace another dialect owns. A dialect operation's actions, a set rule's every-account action included, are its own vendor's labels or an IAM service's (`admin`, `iam`, `kms`, `s3`, `s3express`, `sts`) |
| An IAM action on an anonymous or own-account operation | `acme:Boot` anonymous and authorised as `admin:ServerInfo` | Nothing evaluates an IAM policy there: an anonymous request has no identity, and RustFS answers own-account routes without one. An `admin:` or `s3:` spelling would read as a policy check that never happens, and an authorizer granting it to everyone would open the route. Both take the operation's own vendor label, and an anonymous operation is about no account at all |
| No overlay row | declared in code only | The row is where the precedence and the evidence are reviewed |
| No declaration | overlay row only | A row nothing declares reads as a reviewed decision about behaviour that does not exist |
| Any of the six facts disagreeing | code says 505, overlay says 506 | The record and the behaviour must be one thing |
| No evidence | `evidence: &[]` | A wire shape nobody sourced is a guess with a comment |
| Unacknowledged anonymity | floor admits anonymous, row does not say so | An anonymous operation a reviewer cannot see lets an attacker choose the authentication strength by choosing the operation (`GHSA-5qfg-mf7r-jp3w`, `GHSA-3473-5353-xhwh`) |
| Stale acknowledgement | row says anonymous, floor does not | The other direction; a field that is sometimes wrong stops being read |
| Reserved endpoint family | `HostClass::S3Express` | That face carries constraints written for the operations AWS defines on it |
| Empty selector | `selector: &[]` | An empty conjunction accepts every request that reaches its precedence; the route table allows one only in the fallback band, and a vendor operation is never that row |
| A shadowing declaration about two operations the dialect did not add | `GetBucketAcl` over `ListObjects` | A dialect accounts for the overlaps its own row creates. Signing off on a standard pair is duplication today and a silent approval of a routing change the moment a model upgrade adds a pair nobody has reviewed |
| Undeclared overlap | a row in front of a standard one | The route table's own decision, reached unchanged: a dialect selector that hides an AWS one needs a declaration with a reason and a source |
| An added row wearing an AWS name | `RouteEntry { op_name: "GetObject", .. }` | Sends requests AWS defines to a handler nobody reviewed, whatever it registered as |
| A claim shallower than two segments | `/health`, `/rustfs`, `/iceberg` | The first path-style segment is a bucket: the claim would take a whole bucket away from S3 |
| A malformed or unsourced claim | `/rustfs/admin/`, `/rustfs/%61dmin`, `evidence: &[]` | A claim is the widest change a dialect can make; it names whole unreserved segments and carries a reason and a source |
| Overlapping claims | `/rustfs/admin` and `/rustfs/admin/v3`, in one dialect or two | Which dialect answers must not depend on installation order |
| A claim no row uses | a prefix with no claimed row inside it | It would take its namespace away from S3 to answer nothing |
| An S3-table row inside a claim | `PathLiteral("/rustfs/admin/v3/info")` beside a `/rustfs/admin` claim | S3 routing never looks inside a claim: the row would be dead |
| A template outside the dialect's claims, or malformed | `/other/x`, `/rustfs/{x}/v3`, `{Name}`, `{id}.zip` | A template starts with its claim's segments and binds whole segments |
| A claimed row restating the claim | `Target(Object)`, `PathLiteral`, `HostClass`, `ArnForm`, no or two methods | The claim decides the target, the path, the face and the ARN form; a row names one method |
| A claimed operation naming a bucket or object | `ResourceShape::Bucket` on a claimed route | Inside a claim the path names neither, so nothing would supply the resource |
| A standard operation opting in to the caller's secret | `OperationSpec::standard(..).hand_caller_secret_to_handler()` | No AWS operation needs the key to serve a request |

There is no rule refusing a dialect that changes a standard operation's `OperationSpec`, because
there is no way to write one: a spec is `&'static` data this crate owns, `Operation::spec` returns a
shared reference, and no method mutates one. The absence of an API is a stronger guarantee than a
check.

## Precedence: what a dialect row can and cannot hide

The route table is **first-match**, so the band a dialect row sits in is the whole of what it can
shadow. The occupied bands are in `crates/core/src/route/table.rs`.

Two consequences worth stating before you pick a number.

**A row is only reachable if it is ahead of every standard row that would also accept the request.**
A vendor query key on `GET /{bucket}` placed behind `ListObjects` is never reached: `ListObjects`
pins no query key, so it accepts the request first and the vendor key is silently ignored. The
answer is the wrong answer rather than an error, which is the worst kind.

**Every overlap that placement creates has to be declared.** The default policy is
`ShadowingPolicy::EveryOverlap`, and a client may send two query keys at once, so a dialect row in a
busy method-and-target cell overlaps every other row in that cell — one declaration per pair, each
with a reason and a source.

**A path literal does not make a row disjoint.** The lattice treats the path and the target as
independent dimensions, so `GET /acme/admin/info` on a `PathLiteral` still overlaps every standard
`GET` object row — a client may send `/acme/admin/info?tagging` and both rows accept it. Measured in
rustfs/backlog#1744: such a row owes 10 declarations on `GET` and 11 on `PUT`. (An earlier revision
of this document said it "overlaps nothing"; that was wrong.) Two ways to keep the count small:

- **Claim a path prefix for a whole API surface** — see the next section. Rows inside a claim owe
  no declaration to any S3 row, because S3 routing never sees inside the claim.
- **Pick a sparse cell** when the operation genuinely has to look like an S3 request. `HEAD` on an
  object target holds exactly one standard row, which is why the worked example uses it: one
  overlap, one declaration. A vendor query key on a busy cell — `GET /{bucket}?vendor-key` — owes
  one declaration per standard row in the cell, and that is the price of an S3-shaped request.

Moving a row afterwards is not a free edit. The declaration records which of the two has the lower
precedence, so moving the row behind the operation it declared it shadows is refused as a stale
declaration — the table will not quietly start answering the other operation.

## Path-prefix claims (ADR-0024)

An admin, STS or catalog surface is not S3, and routing it through the S3 table makes every row a
collection of overlap declarations. A dialect instead **claims** a prefix:
`DialectOverlay::claims` holds `PathClaim { prefix, reason, evidence }`, and
`DialectBuilder::declare_claimed::<O>(ClaimedRoute { precedence, rows, shadows })` serves an
operation at one or more `ClaimedRow { template, selector }` inside it.

- **What a claim covers.** A path-style request on the standard endpoint, with no ARN, whose raw
  path is the prefix or continues it with `/`. The router asks the claimed table first; inside a
  claim a claimed row answers or nothing does (`501`, `NO_CLAIMED_ROUTE_MESSAGE`), and the S3 table
  is never consulted. A virtual-hosted request is never covered: its path is a key.
- **Why two segments.** The first path-style segment is a bucket, so `/health` or `/rustfs` would
  take a whole bucket away from S3 and is refused. `/rustfs/admin` takes only the path-style
  spelling of the keys `admin` and `admin/…` in the bucket `rustfs` — what RustFS does today. The
  bucket itself, every other key in it, the same keys virtual-hosted, and a percent-encoded
  spelling of the prefix all remain S3, authorised as S3.
- **Templates.** Literal segments and whole-segment `{name}` parameters. A parameter never matches
  across a separator, an encoded separator or a dot segment in any spelling. Values are decoded
  once after routing and read by the handler as `context.path_params().get("name")` or
  `.parse::<T>("name")`; a value that decodes to a separator, a dot segment, a control character or
  invalid UTF-8 is a `400` before authorisation.
- **Aliases.** One operation may carry any number of rows — `/rustfs/admin/v3/x` and
  `/minio/admin/v3/x` — and the overlay records every one of them.
- **Overlap inside a claim** follows the S3 table's rules: same precedence is a conflict, across
  precedences a `ShadowingDecl` between the two dialect operations is required, and a stale one is
  refused.
- **Service-level.** A claimed operation declares `ResourceShape::Service`. The authorizer, the
  governor, the audit event and the handler context see no bucket and no key — and so does every
  other operation declaring `ResourceShape::Service`, whatever its path names.
- **The caller's secret.** An operation opts in with `hand_caller_secret_to_handler()`. When the
  authenticator hands a secret over, it reaches only those operations by default, and is dropped,
  zeroized, for every other one when the verdict is read.
  `ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()`
  widens it to every handler, for the s3s migration adapter, which cannot build a credential
  without one. A standard operation may not opt in.
- **Presigned.** A dialect operation's `OperationFloor::custom` admits header signatures only; a
  presigned admin request is a `403` before the authorizer. Opting one operation in is
  `OperationFloor::allow_presigned`, which the posture report lists, and nothing does until a
  client is shown to need it.
- **Reported.** Start-up prints `DIALECT_POSTURE claimed_prefixes=[prefix@dialect,…]
  caller_secret_ops=[…]` beside `SECURITY_POSTURE`.

## Action rules, subjects and bound buckets (ADR-0025)

- **Several actions.** `AuthRequirement::any_of(&[..], shape)` or `all_of(&[..], shape)`. The
  facade asks the authorizer one question per action and combines the answers, failing closed:
  any-of allows on any `Allow`, all-of refuses on any refusal, and a count mismatch is
  `Indeterminate`. The overlay's `action` spells the rule: `anyOf(admin:A, admin:B)`.
- **Whose account.** `.about_subject(SubjectRule::Caller)` for an operation on the caller's own
  account, whose action must be a label in the dialect's own namespace (`rustfs:SelfAccountInfo`),
  or `.about_subject(SubjectRule::Query { param, aliases, when_absent })` for one that names an
  account in the query. `aliases` are other exact spellings of the same parameter, as RustFS reads
  `access-key` for `accessKey` (ADR-0029); at most one spelling may appear, once. The subject is
  decoded once before authentication and refused when repeated in any spelling, ambiguous or
  malformed. Both authorizer stages read it as
  `AuthzRequest::subject`, and the handler reads it as `context.subject()`. An anonymous caller is
  never asked about. Whether a named subject is the caller is the authorizer's decision. The
  overlay spells it: `admin:GetUser about query(accessKey|access-key, absent=refused)`, aliases
  after the canonical parameter, which a refusal names.
- **A bound bucket.** `ClaimedRoute { bucket_param: Some("bucket"), .. }` on an operation declaring
  `ResourceShape::Bucket`, where every row's template has `{bucket}`. The raw segment meets the
  path-style S3 bucket rules before authentication, and the governor, the authorizer and the
  handler see that bucket. The overlay's selector ends in `⇒ BucketParam("bucket")`.

## Account sets, query-bound buckets and anonymous bootstrap (ADR-0026)

- **A set of accounts.** `.about_subject(SubjectRule::Set { param: "users", everyone: Some(Everyone
  { param: "all", action: "admin:ListUsers" }) })`. Every named account is asked about under every
  action, and one refusal refuses the request; `all=true` asks the actions and the broader action
  about no subject. A set is decoded once and refused when a member is empty or repeated, when it
  names more than `MAX_SUBJECTS`, when the flag is not exactly `true` or `false`, or when it names
  accounts beside `all=true`. The handler reads `context.subjects()`. The overlay spells it:
  `admin:ListServiceAccounts about each(users, everyone=all ⇒ admin:ListUsers)`. A signed request
  that repeats the parameter is refused by SigV4 canonicalisation today (ADR-0026 (d)).
- **A bucket named in the query.** `ClaimedRoute { bucket_param: Some(BucketParam::Query("bucket")),
  .. }`. The one occurrence of the parameter is read strictly, and its raw value meets the same
  S3 bucket rules as `/{bucket}`, before authentication. The overlay's selector ends in
  `⇒ BucketQuery("bucket")`.
- **Anonymous bootstrap.** An operation that must be anonymous opts in on its own floor with
  `allow_anonymous_after_listing_in_the_posture_report()`, its overlay row sets `anonymous: true`,
  and its action is its own vendor label; the authorizer is still asked.

## Clean-room policy

**Never read MinIO server source when implementing MinIO-compatible behaviour.** The same applies to
Garage. This is a licence boundary, not a preference.

`minio/minio` is AGPL-3.0 and its repository is archived. Behavioural **facts** are not
copyrightable and may be used freely: what bytes go on the wire, which status a request gets, which
element a client expects. The **source** may not be read, copied, vendored, linked or ported —
a line-by-line translation into Rust is a derivative work, and "inspired by" is not what that is.

Derive behaviour from:

- protocol observation — captures, `mc --debug` output, a client library's own trace;
- public API documentation;
- this repository's existing behavioural records under `model/overlays/quirks/`;
- upstream issue and PR **descriptions of behaviour**, stored as a URL plus a sentence you wrote.

`minio-go` is Apache-2.0 and actively maintained; using it as a **client** in a test is unaffected by
any of this. `minio/mint` is Apache-2.0 (and archived) and may be used as an external black-box
runner, pinned by image digest, never as the primary gate.

Enforced by `scripts/check_no_minio_source.sh`, which refuses AGPL licence text outside a short
allowance list, a comment claiming a port from MinIO or Garage, a vendored server tree or any Go
source, and a `minio/minio` submodule or dependency. Its negative controls are in
`scripts/test_guard_scripts.sh`.

A PR that implements a MinIO-compatible behaviour carries this line in its description:

```text
Clean-room: no minio server source was read; behavior derived from protocol observation only.
```
