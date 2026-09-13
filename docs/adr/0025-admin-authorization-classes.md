# ADR-0025: Action rules, subject rules and bound buckets for RustFS's custom-auth admin routes

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because the `Authorizer` contract grows at the granularity of an action and a subject, not of an operation. Also a crate boundary: what `rustfs-gateway-core`'s `AuthRequirement` declares and its router hands the facade (a bound bucket, a subject rule), and what the facade hands the `Authorizer` (`AuthzRequest::subject`).
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 and changes none of its decisions.

rustfs/backlog#1744 migrates RustFS's admin API onto this gateway. ADR-0024's migration plan
left two blockers:

- the 37 routes the inventory marks `auth_mode = custom`;
- binding a template parameter as the authorisation bucket: 11 `{bucket}` routes and 96
  `{warehouse}` routes.

The inventory is `crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, taken at RustFS
`736e4fb8`. It sorts the custom routes into these classes:

| Class | Routes |
|---|---|
| `CredentialOnly` | 10 |
| `ContextualAuthorization` | 9 |
| `MultipleActions` | 9 |
| `S3Action` | 6 |
| `NotImplemented` | 3 |

The other 4 custom-auth routes are `OidcBootstrap` (the `StsFormPost` route is anonymous).

The gateway's contract before this ADR asked the `Authorizer` one question per stage. The question
carried one action, one resource shape, and the routed bucket and key. It had no way to say:

- that one of several actions suffices;
- which account a request acts on;
- that a template parameter is the bucket.

What each class does in RustFS was measured by reading the handlers at `736e4fb8`
(`rustfs/src/admin/**`). The rulings below rest on it.

- **Multiple actions are any-of.** `authorize_admin_request` (`auth.rs:302`) calls
  `evaluate_admin_actions` (`auth.rs:99-107`), which returns `Ok` at the first action that
  passes. It always passes an empty bucket as the resource.
- **`CredentialOnly` handlers make no policy check, with one exception.** They act on the caller's
  own identity: a service account or STS session resolves to its parent
  (`service/caller_identity.rs:157-166`). Password and MFA changes refuse service accounts,
  federated sessions and unresolved parents in the handler (`caller_identity.rs:186-206`).
  - Two routes are misclassified. `list-remote-targets` checks `admin:GetBucketTarget`
    (`replication.rs:606`). `object-zip-downloads/{id}.zip` has no signature at all: the router
    exempts it, and it authenticates by an encrypted bearer token (`object_zip_download.rs:587`).
- **`ContextualAuthorization` depends on data only IAM holds.** Every one of these routes checks
  one fallback action, relaxed for the caller's own account. Two relaxations are used:
  - a deny-only evaluation of that action, as `user-info` and `add-user` do
    (`user.rs:113-121`, `user.rs:597-626`);
  - a comparison with the parent of a service account, as `info-service-account`,
    `delete-service-account` and `update-service-account` do (`service_account.rs:148`,
    `:613-645`, `:728-750`).

  The account is named by a query parameter: `accessKey`, `user` or `userDN`. Absent means the
  caller in some handlers and a `400` in others (`user.rs:580-584`).
- **`S3Action` routes are authorised by an S3 action on a bucket.**
  - `quota/{bucket}`, `quota-stats/{bucket}` and `quota-check/{bucket}` check
    `s3:GetBucketQuota` on the path's bucket (`quota.rs:394-408`, `:579-594`, `:652-667`).
  - `accountinfo` filters its bucket listing per bucket in the handler (`account_info.rs:139-205`).
  - `POST object-zip-downloads` authorises `s3:ListBucket` for each prefix and `s3:GetObject` for
    each object named in its body.
- **The `NotImplemented` label is stale.** `inspect-data` checks `admin:InspectData`.
  `POST service` picks `admin:ServiceRestart`, `admin:ServiceStop` or `admin:ServiceFreeze` by its
  `?action=` query (`system.rs:250-269`).
- **RustFS validates a bucket parameter unevenly.**
  - Quota checks only that it is non-empty (`quota.rs:395`).
  - Heal uses the non-strict validator (`heal.rs:152-158`).
  - The table catalog checks only that `{warehouse}` is non-empty (`table_catalog/mod.rs:1887-1893`),
    yet passes it to policy as the bucket (`:1159`).

## Decision

**(a) Several actions: `AuthRequirement::any_of` and `AuthRequirement::all_of`.**
`AuthRequirement` gains two private facts, set only by its constructors:

- an `ActionRule` (`One`, `AllOf(&[..])` or `AnyOf(&[..])`);
- an optional `SubjectRule`.

The facade asks the `Authorizer` one `authorize_route` question per action, in declaration order,
and asks every one of them so the audit event lists each. `ActionRule::combine` then settles the
answers, and it fails closed:

- an all-of rule keeps its first refusal;
- an any-of rule allows on its first `Allow`; with none, it is `Indeterminate` if any answer was,
  and `Deny` otherwise;
- a count that does not match the rule is `Indeterminate`.

The input stage asks again about the action that decided: the first allowed action of an any-of
rule, or the first action otherwise.

Registration refuses:

- fewer than two actions in a rule;
- a repeated action;
- a malformed action anywhere in the set;
- any rule on a standard operation.

The overlay row records the rendered rule, for example `anyOf(admin:ServerInfo,
admin:Decommission)`. A record that names only the first action is an `ActionMismatch`.

**(b) Whose account: `SubjectRule`, and `AuthzRequest::subject`.** There are two rules:

- `SubjectRule::Caller` says the operation acts only on the caller's own account.
- `SubjectRule::Query { param, when_absent }` says a query parameter names the account.

Before authentication, the facade reads the parameter exactly once, strictly:

- every query key is decoded, so an escaped spelling of the parameter is the parameter;
- a repeated parameter, a malformed escape, invalid UTF-8, a literal `+`, a control character or
  more than 1024 bytes is a `400 InvalidArgument` that names the parameter and never echoes the
  value;
- an absent or empty value is the caller (`WhenAbsent::Caller`) or a `400` (`WhenAbsent::Refuse`).

Both `Authorizer` stages receive the resulting `Subject` (`Caller` or `Named`). So does the handler,
as `RequestContextView::subject()`, so it never parses the query a second time. Only extraction
can produce a `SubjectName`.

Deciding whether a named subject is the caller, a service account of the caller, or subject to a
deny-only evaluation is the `Authorizer`'s job. Only it can look that up.

The facade never asks about a subject for an anonymous caller. Such a request is `Deny` before the
`Authorizer`, even when the operation's floor and ADR-0021 would let an anonymous request reach it.

**(c) A bound bucket: `ClaimedRoute::bucket_param`.** A claimed route may bind one template
parameter as the bucket its operation is authorised on. Such an operation declares
`ResourceShape::Bucket`, and every row's template carries the parameter; otherwise the route is
refused as `ClaimedBucketParam`. The overlay records the binding as ` ⇒ BucketParam("bucket")`.

For each request, the raw, undecoded segment goes through `codec::bucket_label`. That is the
function a path-style `/{bucket}` goes through, so the rules match exactly:

- the name must satisfy `NamePolicy`;
- an escaped spelling is refused;
- the answer is the same `400 InvalidBucketName`;
- all of this happens before authentication.

The governor, both `Authorizer` stages, the audit event and the handler context then see that
`BucketName` and no key. A claimed row's path is not a bucket surface, so the bucket's CORS rules do
not answer a claimed request. `{warehouse}` uses the same binding.

**(d) The rulings, by class.**

| Class (routes) | Ruling |
|---|---|
| `MultipleActions` (9) | **6 are `any_of`.** They are `datausageinfo` and `usage/{bucket}` (`admin:DataUsageInfo`, `s3:ListBucket`); the two `policy-entities` routes (the list-groups, list-users and list-user-policies admin actions); and `pools/list` and `pools/status` (`admin:ServerInfo`, `admin:Decommission`). `usage/{bucket}` also binds `{bucket}`, where RustFS authorises an empty bucket. That is a deliberate tightening. **3 are subject-dependent:** `list-access-keys-bulk` and its `ldap` and `openid` variants. They name a set of users, or `all`, which a single-subject rule cannot express, so they stay unmigrated until a multi-subject rule exists. |
| `CredentialOnly` (10) | **8 are own-account:** `account/info`, `account/password`, `account/mfa` and the five `mfa` routes. Each uses `SubjectRule::Caller` and an action in the dialect's own namespace (`rustfs:SelfAccountInfo`), never `admin:` or `s3:`, which registration refuses. Such an operation is safe without an IAM action only under four conditions: the caller is authenticated (the floor and (b) both enforce it); the request cannot name another account (the rule has no parameter); the `Authorizer` is still asked, so a deployment can deny, and nothing is skipped; and the caller-kind refusals stay where RustFS has them. **`list-remote-targets` is ordinary `admin:GetBucketTarget`**, service-level as in RustFS. **`object-zip-downloads/{id}.zip`** is a bearer-token route with an affixed parameter, and moves to ADR-0024's group 7. |
| `ContextualAuthorization` (9) | **`SubjectRule::Query` with the fallback action.** The rule is `accessKey` with a refused absence for `user-info` and `add-user`; `accessKey` with the caller as absence for `info-access-key`, `info-service-account`, `update-service-account` and `delete-service-account`; `user` with the caller for `list-service-accounts`; and `userDN` with the caller for `idp/ldap/list-access-keys`. The deny-only evaluation and the parent comparison belong to the `Authorizer`. `delete-service-accounts` shares its handler with `delete-service-account`, and where it reads its subject is confirmed when its group migrates [inferred]. |
| `S3Action` (6) | **The three `quota*/{bucket}` routes use `s3:GetBucketQuota`** with `{bucket}` bound. **`get-bucket-quota?bucket=`** names its bucket in the query, so it waits for a query-bound bucket. **`accountinfo`** is own-account (`rustfs:AccountInfo`), and its per-bucket filtering stays in the handler, as for `ListBuckets`. **`POST object-zip-downloads`** is own-account at the route stage. Its `s3:ListBucket` and `s3:GetObject` resources are derived from the body into the existing input stage. |
| `NotImplemented` (3) | **The label is stale, and no new mechanism is needed.** `POST service` becomes four query-predicated claimed rows: `action=restart`, `action=stop`, and `action=freeze` and `action=unfreeze` sharing `admin:ServiceFreeze`. An unknown action is the claim's `501` before authorisation, where RustFS answers `400 InvalidRequest`, which is a documented divergence. The two `inspect-data` routes are ordinary `admin:InspectData`. |

The RustFS findings are recorded on rustfs/backlog#1744:

- the `usage/{bucket}` gate ignores the bucket;
- `list-remote-targets` and `inspect-data` take a query bucket that is not the policy resource;
- `info-service-account` looks up the account before it checks the caller, and its fallback
  ignores an explicit `Deny`;
- `list-service-accounts` lists the caller's own accounts with no policy check;
- the two bulk variants disagree on `ListUsers`.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The class counts come from a `python3` pass over the inventory's `census.by_auth_detail`,
  measured.
- The RustFS semantics were read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`. The file and
  line references are in Context.
- The rule functions, measured by `cargo test -p rustfs-gateway-core --lib -- authz::rule
  registry::reject`:
  - `crates/core/src/authz/rule.rs` holds 11 unit tests for combination, extraction and
    refusal;
  - `crates/core/src/registry/reject_rule_tests.rs` holds 8 tests: every registration refusal,
    and the overlay reading the rendered rule.
- Compile-fail cases, measured:
  - trybuild `authz_subject_name_forged` (E0423) and `authz_requirement_literal` (E0616 twice),
    in `crates/core/tests/compile_fail/`;
  - two doctests, on `SubjectName` (E0423) and on the `AuthRequirement` literal.
- The pipeline, measured by `cargo test -p rustfs-gateway --test integration --
  action_rules_runtime`:
  - an all-of rule missing either action is refused after both were asked;
  - an anonymous own-account request whose floor admits anonymous requests is refused, and the
    `Authorizer` is never asked, even with anonymous admission delegated.
- The proof, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_proof`:
  `class_tests.rs` holds 19 tests covering one route per class and the bound bucket. They check
  that an invalid bucket parameter gets the same status and code as the same name at `/{bucket}`,
  that it is refused before the governor or the `Authorizer` is asked, and that a claimed request
  never reads its bound bucket's CORS document while an S3 request to that bucket does.
- Every assertion added here has a mutation that turns it red. The PR lists each mutation.
- The single-action path allocates nothing new: the per-action question list is an empty `Vec`
  when there is one action [inferred from the code; `tests/request_allocations.rs` is unchanged
  and passes].

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Hand the `Authorizer` the whole action set and one verdict | An existing authorizer reads `request.action` and would judge only the first action. For an all-of rule that is a silent allow. One question per action keeps every existing `Authorizer` correct unchanged. |
| Express all-of as derived resources on the input stage | That machinery already exists, but it cannot say any-of, which is what RustFS uses. The route stage would then still ask about one action and refuse any-of callers who hold only the other. |
| Let `CredentialOnly` skip the `Authorizer` ("authenticated is enough") | This is exactly rustfs/rustfs#4845's shape: a route that reaches a handler without an authorisation question. The `Authorizer` stays in the path, and an own-account label makes the question explicit and reviewable. |
| Give own-account operations an `admin:` action | No IAM policy grants it, so a ring-2 `Authorizer` that evaluates IAM would refuse every ordinary user's own password change, and a reviewer would read the action as a policy check that RustFS never made. |
| Decide "subject is the caller" in the facade | The comparison needs the parent of a service account and a deny-only evaluation, and only the identity store has those. A facade that allowed on "the names are equal" would also allow a service account to act on its parent's siblings' behalf wherever the names happened to match. |
| Read the subject from the query lazily in the handler | The authorizer and the handler would parse the query separately. A repeated parameter or an escaped key is exactly how two parsers come to disagree about which account was authorised. |
| Validate a bound bucket after decoding the parameter | `%70hotos` would become `photos` here, while S3 refuses `/%70hotos`. The raw segment through the same function is the only reading that is identical to S3's. |
| Bind a bucket from a query parameter in this slice | Only `get-bucket-quota` needs it, and its extraction would duplicate (b)'s. It is left for the slice that migrates that group. |
| A posture-report line for own-account operations | The rule is visible in the overlay row (`… about caller`), and registration limits its action to the vendor's namespace. A second listing would add nothing a reviewer cannot already read there [inferred]. |

## Consequences

- **BREAKING**: `rustfs-gateway-core` 0.39.0 and `rustfs-gateway` 0.46.0.
  - `AuthRequirement` has private fields. Build one with `new`, `any_of` or `all_of`, and add
    `.about_subject(..)` when needed. Struct literals no longer compile.
  - `AuthzRequest` gains `subject`. A literal adds `subject: None`.
  - `ClaimedRoute` gains `bucket_param`. A literal adds `bucket_param: None`.
  - `DialectError::ActionMismatch::declared` is a `String`, and `DialectError` gains
    `ClaimedBucketParam`. `RegistryError` gains `InvalidAuthRule`.
  - The overlay `action` of a dialect operation with a rule is the rendered rule.
  - `DialectError` moved to `dialect/error.rs`. Its public path is unchanged.
- **Enforcement:**
  - the tests listed under Evidence;
  - the trybuild cases;
  - the registration refusals;
  - the overlay cross-check against `AuthRequirement::render`.
- **ADR-0024's migration plan changes as follows:**
  - Groups 1 and 3: the `MultipleActions` rulings are resolved, except the three bulk
    access-key routes.
  - Group 4: `CredentialOnly` and `ContextualAuthorization` are resolved.
  - Groups 5 and 6: the bucket binding is resolved.
  - Still open: a multi-subject rule (3 routes), a query-bound bucket (`get-bucket-quota`), and
    everything group 7 already listed.
