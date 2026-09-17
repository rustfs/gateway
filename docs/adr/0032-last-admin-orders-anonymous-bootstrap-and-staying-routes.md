# ADR-0032: The last admin orders: the anonymous OIDC bootstrap generated, the profiling claims, and the routes that stay with RustFS

- Status: Accepted
- Date: 2026-09-18
- Trigger: axiom A4, because whether an admin operation admits an anonymous caller, and whether the gateway serves a route at all, are decided per route, not per group or per dialect. Also a crate boundary: `rustfs-gateway-dialect-rustfs-admin` declares four operations reachable without credentials, installs two more claims, and publishes which inventory routes it deliberately does not serve (`STAYING`), which is what a RustFS deployment must keep routing itself.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 to ADR-0031 and leaves their text unchanged. It applies decisions
ADR-0026 already took — (f) the anonymous bootstrap, (g) the two order-7 routes that stay with
RustFS, (h) `/health` — to the generated dialect, and closes ADR-0024's migration plan.

rustfs/backlog#1744 generates the `rustfs` dialect from the recorded inventory
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`). Orders 1
to 6 landed through rustfs/gateway#824: 292 operations on 584 rows, four groups pending.

Those four groups are orders 7 and 8, 18 routes:

| Group | Routes | What the inventory records |
|---|---|---|
| `oidc` | 8 | 4 `sigv4-admin` (`config` GET, `config/{provider_id}` PUT and DELETE, `validate`), and 4 `anonymous` classed `OidcBootstrap` that RustFS's router admits before any login (`authorize/{provider_id}`, `callback/{provider_id}`, `logout`, `providers`) |
| `sts` | 2 | `GET is-admin` (`sigv4-admin`, `admin:*`) and `POST /` (`anonymous`, `StsFormPost`) |
| `object_zip_download` | 2 | `POST object-zip-downloads` (`custom`, `S3Action`) and `GET object-zip-downloads/{id}.zip` (`custom`, `CredentialOnly`, router-anonymous) |
| `health` | 6 | `GET` and `HEAD` of `/health` and `/health/ready` (`anonymous`, `Health`), and `GET /profile/cpu`, `GET /profile/memory` (`sigv4-admin`, `admin:Profiling`), none under an admin prefix |

Raising the migrated order, the generator refused the first anonymous route ("an anonymous route
in a migrated group has no ruling"): it had no way to declare one, and no way to leave a single
route of a migrated group undeclared, because `PENDING` counts groups.

What was already decided:

- ADR-0026 (f): each OIDC bootstrap route is a claimed operation whose floor calls
  `allow_anonymous_after_listing_in_the_posture_report()`, whose overlay row acknowledges
  `anonymous: true`, and whose action is its own vendor label; the `Authorizer` is still asked,
  with no identity; presigned requests stay refused. `rustfs-gateway-core` already refuses an
  anonymous dialect operation that names an IAM action or a subject rule (rustfs/gateway#798).
- ADR-0026 (g): `GET object-zip-downloads/{id}.zip` needs an affixed parameter and a per-operation
  bearer scheme, and STS `POST /` needs its own ADR; both stay with RustFS.
- ADR-0026 (h): `/health` belongs in the server's probe layer; `/profile/cpu` and
  `/profile/memory` remain two-segment claims under ADR-0024.
- ADR-0025 (d): `POST object-zip-downloads` is own-account at the route stage, and its
  `s3:ListBucket` and `s3:GetObject` resources are derived from the body into the input stage.

## Decision

**(a) The generator declares an anonymous operation only when the inventory and a ruling agree.**
A ruling's form may opt in to anonymous requests. The generator accepts that opt-in exactly on a
route the inventory records as `anonymous`, and refuses an `anonymous` route whose ruling does not
opt in, so neither side alone can make an operation reachable without credentials. An anonymous
rule names exactly one action, a label in the dialect's own namespace, and no account; an IAM
action, an any-of rule or a subject rule is refused at generation, as core refuses it at
registration. The four labels are RustFS's handler names without `Handler` (ADR-0028 (a)):
`rustfs:OidcAuthorize`, `rustfs:OidcCallback`, `rustfs:OidcLogout`, `rustfs:ListOidcProviders`.
The generated module uses `admin::anonymous_floor`, records `anonymous: true` in its overlay row
and in its `RouteRecord`, and says why in its documentation. Nothing else in the claims becomes
anonymous: 299 of 303 operations keep the privileged, header-signed-only floor.

**(b) A route may stay with RustFS, by name and with its reason.** The generator takes a list of
`(method, path, reason)` next to the rulings. A listed route of a migrated group is declared as no
operation and published in the dialect's `STAYING` table with its group and reason; once every
group is migrated, a listed route the inventory does not record is refused. Seven routes stay:

- `GET object-zip-downloads/{id}.zip` and STS `POST /`, for ADR-0026 (g)'s reasons;
- `POST object-zip-downloads`, which is new here: a generated operation derives no resources from
  its body (every one is `NoDerived`), so it cannot give the input stage the `s3:ListBucket` and
  `s3:GetObject` questions ADR-0025 (d) requires, and the route only mints the token the download
  route consumes, which stays with RustFS. Serving half of the pair would move a credential-minting
  step behind the gateway while its check stayed behind RustFS;
- the four `/health` and `/health/ready` routes, for ADR-0026 (h)'s reason.

So a deployment can read from the dialect exactly which admin routes it must keep routing itself,
and `PENDING` is empty: every registration group of ADR-0024's plan is migrated.

**(c) Two more claims, and a surface without an alias.** The dialect claims `/profile/cpu` and
`/profile/memory`, each two segments deep, as ADR-0024 and ADR-0026 (h) planned; a path-style
bucket named `profile` loses its `cpu` and `memory` keys, as on RustFS. Their operations are
`rustfs:GetProfileCpu` and `rustfs:GetProfileMemory`, on one row each: RustFS serves no compat
spelling, so they are the only operations without an alias row.

**(d) `GET is-admin` is an ordinary `sigv4-admin` operation** with the inventory's action,
`admin:*`. The wildcard is RustFS's own spelling of "any admin action" and is what its handler
asks its policy; the gateway hands it to the `Authorizer` verbatim and gives it no meaning of its
own.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The route counts come from a `python3` pass over the inventory's rows by group, measured: 18
  routes, 9 anonymous by the inventory (4 `OidcBootstrap`, 4 `Health`, 1 `StsFormPost`), 7 staying.
- The generator, measured by `cargo test -p xtask -- rustfs_admin_dialect`: the drift check over
  308 files; an anonymous route declared only under an opting-in ruling, rendered with the anonymous
  floor, the overlay acknowledgement and the record; an opt-in on a custom-auth route, a missing
  opt-in, an IAM action, an any-of rule and an account each refused; a staying route recorded and
  never declared, a stale one refused; the recorded plan's seven staying routes, four anonymous
  operations, 303 operations and no pending group.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin`: 604 rows route;
  181 parameters across 96 templates; six claims assemble; exactly four operations admit anonymous
  requests, each matching its record, none presigned, and only own-account and bootstrap operations
  carry a vendor label; the census by group, no group pending, the seven staying routes by name and
  none of them declared, and declared + 49 compat rows + 7 staying = 356.
- The proof, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`: every
  inventory route is a declared operation, a compat alias or a staying route; the 596 rows that are
  not bootstrap rows refuse an unsigned request without asking the `Authorizer`; the eight
  bootstrap rows are admitted only when the `Authorizer`, asked the operation's own label with no
  identity, bucket or account, allows, are refused before the handler when it denies, are judged
  as their caller when signed, and hold no secret; all 596 presignable rows, bootstrap rows
  included, refuse a presigned request.
- Every assertion added here has a mutation that turns it red. The PR lists each mutation.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Let the inventory's `anonymous` mode alone declare an anonymous operation | `/health` and STS `POST /` are `anonymous` in the inventory too; an opt-in that the recorded data can flip without a reviewed ruling is not an opt-in. |
| Keep `object_zip_download` and `health` as pending groups | `PENDING` would then never empty, and a deployment could not tell a group nobody has reached from a route the gateway has decided not to serve. |
| Generate `POST object-zip-downloads` as own-account only, leaving the S3 checks in the handler | That is what `accountinfo` does for a listing; here the body names the objects a token will later release, so the unasked questions are the authorisation. ADR-0025 (d) asked for them at the input stage. |
| Give the profiling routes an alias prefix | RustFS serves none; an alias row nobody registered is a route RustFS does not have. |
| Claim `/profile` | One segment: it would take the bucket `profile` away from S3 (ADR-0024 (a)). |

## Consequences

- **BREAKING**: `rustfs-gateway-dialect-rustfs-admin` 0.7.0. `RouteRecord` gains `anonymous`
  (a literal adds `anonymous: false`); the crate exports `STAYING` and `StayingRoute`; `CLAIMS` has
  six entries; four operations are reachable without credentials and appear in the start-up
  `SECURITY_POSTURE anonymous_reachable_ops=[…]` line. `rustfs-gateway-core` is unchanged.
- **Enforcement:** the tests listed under Evidence; core's registration refusals for an anonymous
  dialect operation; the overlay's anonymous acknowledgement checked in both directions; the
  generator's refusals in (a) and (b).
- **ADR-0024's migration plan is complete on the gateway side**: 349 of the inventory's 356 routes
  are served (300 canonical routes as 303 operations, 49 compat rows), and seven stay with RustFS
  by name. What remains for rustfs/backlog#1744 is RustFS's: registering handlers against the
  dialect, the probe layer, and the two follow-ups ADR-0026 (g) describes (a per-operation bearer
  scheme with affixed parameters, and an STS surface).
