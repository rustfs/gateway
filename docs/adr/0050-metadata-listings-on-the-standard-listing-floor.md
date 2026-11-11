# ADR-0050: The metadata listings on the standard listing floor

- Status: Accepted
- Date: 2026-11-11
- Trigger: a RustFS-profile behaviour difference (rustfs/gateway#1588), narrowing for two claimed operations the floor rulings of ADR-0024 (f), ADR-0035 and ADR-0021
- Supersedes / Superseded by: none

## Context

RustFS serves a listing extension on its S3 port: `GET /{bucket}?list-type=2&metadata=true` and
`GET /{bucket}?versions&metadata=true`. Each answers the ordinary listing document with each
entry's user metadata added. RustFS's metadata route claims the request before its admin router
and its S3 service. It requires a bucket `GET` whose first `metadata` value is exactly `true`.
It picks the versions listing when the query names `versions`, and otherwise the V2 listing when
the first `list-type` value is `2`.

The route then authorises the request as a bucket listing. A signed caller's credentials are
resolved, and an unsigned caller stays anonymous for the bucket policy. The action is
`s3:ListBucketVersions` or `s3:ListBucket` on the bucket. That is the same decision RustFS makes
for its standard listings.

The RustFS dialect now serves the two requests as `rustfs:ListObjectVersionsWithMetadata` and
`rustfs:ListObjectsV2WithMetadata`, two S3-table rows ahead of the standard listing rows. Every
other dialect operation sits on a privileged floor (`OperationFloor::custom`). Three accepted
records rest on that:

- ADR-0024 (f) keeps every dialect operation on `OperationFloor::custom`.
- ADR-0035 says a third-party operation refuses every presigned URL.
- ADR-0021 keeps a privileged operation out of anonymous delegation.

A privileged floor here would refuse an anonymous listing that a bucket policy allows, and a
presigned listing, even where the deployment admits both for `ListObjectsV2`. A client asking for
metadata would be held to a stricter rule than the same client listing without it. That is a
behaviour difference under the RustFS profile. A floor that admits more than the standard
listing's would be a way around the standard listing's floor.

## Decision

The two metadata listings, and no other dialect operation, use `admin::listing_floor`:

```rust
OperationFloor::builtin(name, SigService::S3)
```

That is exactly the floor of `ListObjectsV2` and `ListObjectVersions`. It is not privileged and
admits header signatures. A deployment's floor admits an anonymous request, or a presigned URL,
on these two exactly where it admits one on the standard listings:

- anonymous only under `delegate_anonymous_to_authorizer_after_listing_in_the_posture_report`;
- presigned only under `admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report`;
- a SigV2 presigned URL only under the SigV2 compatibility policy as well.

Every admitted request is still the authorizer's to decide, for the listing action on the bucket.
The overlay row records `anonymous: false`, because the operation itself opts into nothing.
The posture line names the two operations wherever it names the standard listings.

The generator owns the choice. An inventory row claimed by `rustfs/src/app/metadata_route.rs`
must record the class `SignedOrAnonymousThenBucketListing`, and only such a row renders
`admin::listing_floor`. A presigned ruling on such a row is refused. The admin router's eight
extension rows, the claimed admin operations and the zip pair keep their floors unchanged.
ADR-0024, ADR-0035 and ADR-0021 are not edited. This record narrows them for these two operations.

## Evidence

- RustFS's metadata route: https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/rustfs/src/app/metadata_route.rs. Its selector requires a first `metadata` value of exactly `true` and tries `versions` before `list-type=2`. Its access check keeps an unsigned caller anonymous and authorises the matching listing action on the bucket. Read from source.
- The dialect crate's test `each_metadata_listing_floor_is_exactly_its_standard_listings_floor`
  compares each floor with the standard listing's under all four combinations of the anonymous
  and presigned policies.
- The goldens tests under `rustfs_admin_dialect::metadata_listing_tests` cover the assembled
  service on the default floor and on the RustFS profile's floor.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| The privileged floor (`admin::floor`) | Stricter than the standard listing, and it refuses an anonymous listing a bucket policy allows, which RustFS serves. |
| `admin::anonymous_floor` | Admits anonymous requests under every policy, which is weaker than the standard listing under the default floor. |
| `admin::presigned_floor` | Refuses anonymous requests and SigV2 under every policy, so it differs from the standard listing in both directions. |

## Consequences

A host that registers the standard listings under the RustFS dialect must also register these
two operations. Without a handler, a request carrying `metadata=true` is answered `501`. It is
no longer served as a standard listing that silently drops the metadata it asked for.
