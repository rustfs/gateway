# ADR-0028: Subject rules for RustFS's order-4 admin routes: own-account labels, refused absences, and alias spellings

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because whose account an admin operation acts on is decided per operation and per query parameter, and the `Authorizer` is asked about that account. Also a crate boundary: what `rustfs-gateway-dialect-rustfs-admin` declares and records for 21 operations (`RouteRecord::subject`), and what RustFS's handlers must read instead of the query.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 to ADR-0027. It narrows one row of ADR-0025 (d), the absence rule of
four `ContextualAuthorization` routes (see (b)), and leaves the text of ADR-0025 unchanged.

rustfs/backlog#1744 generates the `rustfs` dialect from the recorded inventory
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`) with
`cargo xtask rustfs-admin-dialect`. Orders 1 to 3 landed in rustfs/gateway#801 and #805: 155
operations on 310 rows.

ADR-0024's order 4 is five registration groups and 66 routes: `user` 37, `idp_compat` 13, `mfa` 8,
`replication_handler` 6 and `account` 2. Raising the migrated order to 4, the generator refused
the first custom-auth route it met ("a custom route in a migrated group has no ruling"). All 24
custom-auth routes of order 4 lacked a ruling:

| Class | Routes |
|---|---|
| `CredentialOnly` | 9 |
| `ContextualAuthorization` | 9 |
| `MultipleActions` | 5 |
| `S3Action` | 1 |

The other 42 routes are `sigv4-admin` and planned under the existing rules. Ten carry templates,
with 16 service-level parameters (`group`, `idp_type`, `name`, `target_type`, `target_name`,
`operation`, `user_provider`). None is a bucket, and no two rows overlap.

ADR-0025 (d) and ADR-0026 (c) decided the classes. What each handler does was read at `736e4fb8`
(`rustfs/src/admin/handlers/**`) before the generator was given its rules:

- **Own-account handlers** are `SelfAccountInfoHandler`, `AccountMfaStatusHandler`,
  `AccountInfoHandler`, `MfaChallengeHandler`, `AccountMfaActivateHandler`,
  `AccountMfaDisableHandler`, `AccountMfaEnrollHandler`, `AccountMfaRecoveryCodesHandler` and
  `ChangeOwnPasswordHandler`. None of them reads an account from the query.
- **An absent account is refused by six handlers.** `GetUserInfo` and `AddUser` read
  `AddUserQuery` (`user.rs:60-65`, `:568-584`). `InfoServiceAccount`, `UpdateServiceAccount` and
  `DeleteServiceAccount` read `AccessKeyQuery` (`service_account.rs:528-531`). All of them answer
  `400 InvalidArgument` ("access key is empty") when the value is empty. `delete-service-accounts`
  is registered with the same `DeleteServiceAccount` handler; the inventory's `handler` column
  says so.
- **An absent account is the caller in three handlers.** `InfoAccessKey` falls back to the
  caller's access key. `ListServiceAccount` reads `user` and lists the caller's own accounts
  without it. `ListAccessKeysLdap` falls back to the caller's user name
  (`idp_compat.rs:692-722`).
- **The fallback actions** are `admin:GetUser`, `admin:CreateUser`,
  `admin:ListServiceAccounts`, `admin:UpdateServiceAccount` and `admin:RemoveServiceAccount`. The
  wire spellings are the strum `serialize` names in `crates/policy/src/policy/action.rs`.
- **The two `policy-entities` routes** share `ListPolicyEntitiesBuiltin`, which accepts any of
  `admin:ListGroups`, `admin:ListUsers` and `admin:ListUserPolicies` (`policies.rs:748-754`).
- **RustFS reads alias spellings.** `accessKey` is also read as `access-key` (serde `alias`).
  `ListAccessKeysLdap` reads `userDN`, `user-dn` or `user`, and the last one wins
  (`idp_compat.rs:866`).
- **`ListAccessKeysLdap` also asks `admin:ListUsers`** when the named DN is not the caller
  (`idp_compat.rs:709-712`).

## Decision

**(a) An own-account operation's label is RustFS's handler name.** Each of the nine own-account
operations is `SubjectRule::Caller` with one action: `rustfs:` followed by the handler's name
without `Handler`. The labels are `rustfs:SelfAccountInfo`, `rustfs:AccountMfaStatus`,
`rustfs:AccountInfo`, `rustfs:MfaChallenge`, `rustfs:AccountMfaActivate`,
`rustfs:AccountMfaDisable`, `rustfs:AccountMfaEnroll`, `rustfs:AccountMfaRecoveryCodes` and
`rustfs:ChangeOwnPassword`. ADR-0025 (d) gave two of these as examples, and the rule reproduces
both. A label names what RustFS runs, so a reviewer can find the code, and no IAM policy grants
it by accident.

The generator refuses:

- an own-account rule with an IAM action, another vendor's label, or more than one action;
- a `rustfs:` label on any other operation, whether a ruling or the inventory supplies it.

Registration refuses the first as well (ADR-0025). The second is the generator's own, stricter
rule.

**(b) Absence follows the handler: `Refuse` where RustFS answers `400`.**

| Route | Rule |
|---|---|
| `GET user-info` | `admin:GetUser` about `query(accessKey, absent=refused)` |
| `PUT add-user` | `admin:CreateUser` about `query(accessKey, absent=refused)` |
| `GET info-service-account` | `admin:ListServiceAccounts` about `query(accessKey, absent=refused)` |
| `POST update-service-account` | `admin:UpdateServiceAccount` about `query(accessKey, absent=refused)` |
| `DELETE delete-service-account`, `DELETE delete-service-accounts` | `admin:RemoveServiceAccount` about `query(accessKey, absent=refused)` |
| `GET info-access-key` | `admin:ListServiceAccounts` about `query(accessKey, absent=caller)` |
| `GET list-service-accounts` | `admin:ListServiceAccounts` about `query(user, absent=caller)` |
| `GET idp/ldap/list-access-keys` | `admin:ListServiceAccounts` about `query(userDN, absent=caller)` |

ADR-0025 (d) wrote "the caller as absence" for `info-service-account`, `update-service-account`
and `delete-service-account`, and inferred the same for `delete-service-accounts`. The handlers
refuse instead. This ADR rules `Refuse` for all four:

- it is what RustFS answers;
- it fails closed. With `Caller`, a request that names nobody would be authorised about the
  caller's own account and reach a handler that needs an account to act on. For
  `delete-service-account` that means deleting "the caller's" key.

The refusal is the facade's `400 InvalidArgument` naming the parameter before authentication,
where RustFS answers after it.

**(c) An alias spelling names no account.** The facade reads only the parameter the rule names
(`accessKey`, `user`, `userDN`), which is the spelling RustFS's documented routes and MinIO's
admin client send [inferred]. An alias (`access-key`, `user-dn`, `user` on the LDAP route) or the
parameter in another case is therefore an absent account: the caller, or a `400`, as (b) rules.

This is safe only because the handler acts on `RequestContextView::subject()` and never
re-reads the query (ADR-0025 (b)). Under that contract, an alias cannot name an account the
`Authorizer` was not asked about. The divergence is recorded:
`GET info-access-key?access-key=bob` answers the caller's own key on the gateway and `bob`'s on
RustFS.

**(d) `idp/ldap/list-access-keys` asks one action about the named account.** RustFS also asks
`admin:ListUsers` for a DN that is not the caller's. The gateway cannot say "unless it is the
caller" without deciding caller-ness in the facade, which ADR-0025 rejected. This is the same
reasoning as ADR-0026 (c) for the bulk variants. A deployment `Authorizer` that wants RustFS's
behaviour answers the `admin:ListServiceAccounts` question about a non-caller account with
`admin:ListUsers` as well.

**(e) The bulk listings take ADR-0026 (c)'s rule, and (d) stays fail-closed.** All three are
`admin:ListServiceAccounts about each(users, everyone=all ⇒ admin:ListUsers)`. Naming two
accounts in a signed request still fails at SigV4 canonicalisation, before anything reads the set.
The generated module says so, and a test proves it. `rustfs-gateway-sig` is not changed.

**(f) What the generator emits.**

- A subject-ruled module declares `pub const SUBJECT: SubjectRule`. Its `AUTH` is
  `….about_subject(SUBJECT)`, and its `RECORD.subject` is `Some(SUBJECT)`.
- The overlay's action is the rendered rule, for example
  `admin:GetUser about query(accessKey, absent=refused)`.
- A subject-ruled row cites ADR-0028; a set-ruled row also cites ADR-0026.
- The rulings move to `xtask/src/rustfs_admin_dialect/rulings.rs`.
- The generated table is split into `table.rs` (`PENDING`, the commit) and `table/overlay.rs`,
  `table/routes.rs` and `table/fold.rs`, because one file would pass the 800-line ceiling at
  order 4. `table/` is wholly generated, like `ops/`, and the drift check covers it.
- rustfmt runs in parallel lanes. The drift check formats 226 files, which took about 7s one
  after another.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The RustFS semantics were read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`. The file and
  line references are in Context.
- The class counts, group counts and template parameters come from a `python3` pass over the
  inventory, measured.
- The generator, measured by `cargo test -p xtask --bin xtask rustfs_admin_dialect` (20 tests):
  - the drift check over 226 files;
  - an extra file in `table/` counts as drift, as one in `ops/` does;
  - each subject shape rendered as core renders it;
  - the recorded plan's 21 subject rules, listed by name;
  - the 29 caller-secret opt-ins, listed by name;
  - eleven rule-shape refusals and the vendor-label refusal for an inventory action.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin` (17 tests):
  - 442 rows route;
  - a subject parameter changes no route (210 requests);
  - 35 parameters on 27 templates refuse dot segments and separators;
  - each operation's declared subject equals its record;
  - only an own-account operation carries a `rustfs:` action.
- The service, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`
  (19 tests). Every row is asked about exactly its declared account, and the handler is handed the
  same one. In `subject_tests.rs`:
  - 36 refused absences are a `400` naming `accessKey` before any question;
  - 30 caller absences and alias spellings are about the caller;
  - 36 own-account requests naming other accounts are about the caller;
  - 90 repeated or malformed accounts and 42 malformed sets are a `400` before authentication;
  - `all=true` asks both actions about no account, and is refused without `admin:ListUsers`;
  - a second `users` smuggled after signing is refused before any question.
- Every assertion added here has a mutation that turns it red. The PR lists each one.

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Keep ADR-0025's "caller as absence" for the three service-account routes | RustFS refuses. The gateway would authorise a request about the caller that the handler cannot serve, and for a delete the nearest reading is the caller's own key. |
| Read the alias spellings too | Two spellings of one account are two parsers' worth of ambiguity: `accessKey=a&access-key=b` is the disagreement ADR-0025 closed. Core's extraction reads one parameter, and a second is a core change with no client that needs it [inferred]. |
| Refuse an alias spelling with a `400` | That needs a per-rule list of refused keys in core. Under (c) an alias already cannot widen what was authorised, because the handler reads the context. It can be added if a client is found sending one. |
| An own-account label per route shape (`rustfs:GetV3AccountInfo`) | It would say nothing about what runs. The handler name is what a reviewer greps for, and ADR-0025 already used two of them. |
| Ask `admin:ListUsers` as an all-of on `idp/ldap/list-access-keys` | Every self-listing would then need `admin:ListUsers`, which RustFS does not require. |
| Admit a repeated `users` now | That is ADR-0026 (d)'s HIGH-RISK signature change, and it has its own task. |
| Keep one generated `table.rs` with an allowance | The file grows with every order. One list per file keeps each under the ceiling through order 8, with no exception to review. |

## Consequences

- **BREAKING**: `rustfs-gateway-dialect-rustfs-admin` 0.3.0. `RouteRecord` gains
  `subject: Option<SubjectRule>`, so a literal must add it. Core, the facade and the signature
  crate are unchanged.
- **Handler contract**: a RustFS handler for any of the 21 operations reads the account from
  `RequestContextView::subject()` or `subjects()`, never from the query. That is what makes (c)
  safe.
- **Enforcement**:
  - the tests under Evidence;
  - the generator's refusals;
  - registration's own-account namespace rule;
  - the overlay cross-check against `AuthRequirement::render`.
- **ADR-0024's migration plan**: order 4 is migrated, with 221 operations on 442 rows. Orders 5
  to 8 remain: 10 groups and 138 routes, next the bucket bindings of order 5.
