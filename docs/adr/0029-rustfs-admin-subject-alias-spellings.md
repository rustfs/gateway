# ADR-0029: RustFS's alias spellings of a subject parameter name the same account

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because whose account an admin operation acts on is decided per operation and per query parameter, and the `Authorizer` is asked about that account. Also a crate boundary: `rustfs-gateway-core`'s `SubjectRule::Query` gains a field, and what `rustfs-gateway-dialect-rustfs-admin` declares for nine operations changes.
- Supersedes / Superseded by: none

## Context

This ADR replaces ADR-0028 (c) and leaves the rest of ADR-0028 in force. ADR-0028's text is not
changed. The same approach was used when ADR-0028 narrowed a row of ADR-0025 (d).

ADR-0028 (c) ruled that an alias spelling of a subject parameter names no account. The facade
read only the canonical parameter, so an alias was an absent account: the caller, or a `400`.
That was safe against privilege escalation, because a handler acts only on
`RequestContextView::subject()`. It was still wrong for the caller.
`GET info-access-key?access-key=bob` answered the caller's own key on the gateway and `bob`'s on
RustFS. A client that sends the alias would get another account's object, with a `200`, and no
way to tell.

What RustFS reads was re-read at `62cc19e937c8cac4a14f4a353405a19d19319bd7` (read-only checkout):

- `AccessKeyQuery` (`rustfs/src/admin/handlers/service_account.rs:519-523`) is
  `#[serde(rename = "accessKey", alias = "access-key")]`. `InfoServiceAccount`,
  `UpdateServiceAccount`, `DeleteServiceAccount` and `InfoAccessKey` parse it with
  `serde_urlencoded::from_bytes`.
- `AddUserQuery` (`rustfs/src/admin/handlers/user.rs:59-64`) has the same attribute. `GetUserInfo`
  and `AddUser` read it.
- `SingleUserAccessKeysQuery::parse` (`rustfs/src/admin/handlers/idp_compat.rs:786-800`) matches
  `"userDN" | "user-dn" | "user"`, so the last of them wins.
- `ListServiceAccountQuery` (`service_account.rs:920-923`) has `user` alone, with no alias.
- Every key comparison is exact: serde field names and a string `match`. So neither parser reads
  `AccessKey` or `access_key`.
- serde refuses a struct field that appears twice, under one spelling or two, as a
  duplicate-field error. The handlers turn that into `InvalidArgument`. [inferred from serde's
  derive and the `map_err` at each call site]

## Decision

**(a) An alias names the same account as its parameter.** `SubjectRule::Query` gains
`aliases: &'static [&'static str]`. The facade reads the one value that the canonical parameter or
any alias carries, decodes it as strictly as before, and treats it as the canonical parameter in
every way:

- an empty alias is an absence;
- a refusal names the canonical parameter;
- the handler receives the same `subject()`.

**(b) One spelling, once.** Two appearances between the spellings are a
`400 InvalidArgument` (`SubjectError::Repeated`) before authentication. That covers one spelling
twice, and two spellings once each, with the same value or not. For `accessKey`/`access-key`, this
is what RustFS's serde answers. For the LDAP DN, RustFS keeps the last spelling. The gateway
refuses instead, because two parsers can disagree about "the last one", and ADR-0025 closed that
disagreement for the canonical parameter.

**(c) The declared aliases are exactly RustFS's.**

| Operation | Rule |
|---|---|
| `user-info`, `add-user`, `info-service-account`, `update-service-account`, `delete-service-account`, `delete-service-accounts` | `query(accessKey\|access-key, absent=refused)` |
| `info-access-key` | `query(accessKey\|access-key, absent=caller)` |
| `idp/ldap/list-access-keys` | `query(userDN\|user-dn\|user, absent=caller)` |
| `list-service-accounts` | `query(user, absent=caller)` |

The overlay renders the aliases after the canonical parameter, joined with `|`. Some spellings
stay absences, as they are on RustFS:

- the parameter in another case;
- another rule's alias, such as `user-dn` on `info-access-key`.

**(d) Registration and the generator refuse ambiguous aliases.**

- Core's `SubjectRule::fault` refuses an alias that is not RFC 3986 unreserved, one equal to the
  parameter, and one listed twice.
- A query-bound bucket (ADR-0026) may not be the parameter or any alias.
- The generator refuses the same, and also an alias equal to the query key that selects the form.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The RustFS parsers were read at `62cc19e9`. The file and line references are in Context. The
  duplicate-field refusal is `[inferred]`, as noted there.
- Core, measured by `cargo test -p rustfs-gateway-core --lib` (546 tests):
  - `authz::query` has two new tests: an alias is the parameter, and two spellings are a repeat;
  - `authz::rule_tests` has four new tests:
    - an alias names the same account and an empty one is an absence;
    - two spellings are `Repeated`, naming `accessKey`;
    - a malformed, self-equal or twice-listed alias cannot register;
    - the render;
  - `registry::reject_rule_tests` refuses a query bucket that is an alias of the account parameter.
- The generator, measured by `cargo test -p xtask --bin xtask rustfs_admin_dialect` (20 tests).
  The recorded plan renders the nine rules above, and four new refusals cover an alias that is:
  - not unreserved;
  - equal to the parameter;
  - listed twice;
  - equal to the selecting key.
- The service, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`
  through the assembled facade. `subject_tests.rs` has three new tests:
  - every named-account operation declares exactly `RUSTFS_ALIASES`;
  - 18 alias requests (9 spellings on 2 templates) are asked about `account-1`, and the handler is
    handed `named:account-1`;
  - 74 requests with two spellings, a repeated alias or a malformed alias value are a `400` naming
    the canonical parameter, before any question.
- Red first, measured: before the core change, `an_alias_spelling_names_the_account` and
  `n_two_spellings_of_one_account_are_refused_before_authorising` failed, and the other eight
  subject tests passed.
- Every assertion added here has a mutation that turns it red. The PR lists each one.

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Keep ADR-0028 (c): an alias names no account | A client sending `access-key` gets the caller's object, with a `200` and no way to know. That is a correctness hazard and a migration break. |
| Refuse an alias with a `400` | That fails closed, but it breaks every client that sends RustFS's alias, with no ambiguity to justify it: one spelling at a time has one meaning. |
| Keep RustFS's last-wins on the LDAP DN | "Last" is a parser's opinion. Two parsers that disagree on it are ADR-0025's disagreement again. RustFS refuses the two `accessKey` spellings, so refusing is also the more RustFS-like answer. |
| Accept any case of the parameter | RustFS compares exactly, so a case-folded spelling would name an account RustFS does not read. |
| Per-dialect alias handling outside core | Extraction is core's, and it must be the one reader of the subject. A second reader beside it is the disagreement ADR-0025 closed. |

## Consequences

- **BREAKING**:
  - `rustfs-gateway-core` 0.42.0: a `SubjectRule::Query` literal must add `aliases` (`&[]` keeps
    the old meaning), and a pattern that names every field must too.
  - `rustfs-gateway-dialect-rustfs-admin` 0.4.0: eight operations now accept an alias spelling, and
    their rendered actions change.
- **Handler contract, unchanged**: a handler reads the account from
  `RequestContextView::subject()`, never from the query. It now receives the same account RustFS
  would have read.
- **Enforcement**:
  - the tests under Evidence;
  - core's registration fault and the generator's refusals;
  - the overlay cross-check against `AuthRequirement::render`;
  - the drift check.
