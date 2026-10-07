# The RustFS profile

The RustFS profile is the set of legacy RustFS readings a gateway in front of RustFS applies so
that the clients RustFS serves today keep seeing what they see today. It is one reviewable entity
(rustfs/backlog#2751): two preset methods apply it, one start-up line names what it applied, and
one golden pins the whole of it.

| What | Where |
| --- | --- |
| The builder half | `ServiceBuilder::rustfs_profile` (`crates/gateway/src/builder/rustfs_profile.rs`) |
| The authenticator half | `SigV4Authenticator::rustfs_profile` (same file) |
| The observation | the `PROFILE_POSTURE` start-up line, read back from the assembled state by `ServiceBuilder::legacy_switches`, never from whether the preset was called; the floor, the lifetime rule, the naming rules and the governor keep their own lines |
| The whole report | `S3Service::startup_posture`, the text of every posture line as logged |
| The golden | `crates/gateway/tests/golden/rustfs-profile-posture.txt`, rendered from the preset over the reference filesystem backend (`crates/gateway/tests/rustfs_profile.rs`) |
| The launcher held to it | `compat/sut/src/service.rs` calls the two halves and nothing else of the profile; `compat/sut/src/service/tests/rustfs_profile_tests.rs` compares its posture to the golden byte for byte |

A re-pin of the gateway changes what the profile does only through the preset and the modules it
names. The diff of the preset is the diff of the profile, and the golden goes red when the
assembled result moves. Regenerate it deliberately and say why in the pull request:

```bash
UPDATE_GOLDEN=1 cargo test -p rustfs-gateway --test integration rustfs_profile::
```

## What stays the host's

The preset applies readings; it installs no instance and takes no deployment choice. These stay
with the assembly that calls it, before or after the call:

- the credential provider, regions, authorizer, bucket-owner source and CORS source;
- the host resolver (`LegacyRustfsVirtualHosts` in front of RustFS) and the trace source (a host
  hands its own identifier over through `HostRequestId`);
- `sse_config`: whether a customer key over cleartext is refused at all is
  `RUSTFS_SSE_C_REQUIRE_TLS`'s decision; the profile only fixes where and how the refusal is
  answered;
- the CORS cache lifetime, the limits and the deadlines (`ServiceConfig`), which the bridge takes
  from RustFS configuration;
- the fallback CORS origins, the unread-body drain and the governor rates: the preset installs
  RustFS's defaults (no fallback origins; a 300-second idle drain; every layer unlimited), and a
  call to `answer_cors_as_legacy_rustfs`, `drain_unread_request_bodies` or
  `framework_governor_rates` after the preset replaces them — one before it is replaced by it.

## The switches

"Unregistered" means rustfs/backlog#2684 has no entry for the reading yet; the register has no item
numbers, so an entry is named by its heading. The exit condition is the register's intended
behaviour where it states one, and the core default otherwise; an unregistered reading is
registered before it is removed.

### Builder half: `ServiceBuilder::rustfs_profile`

| Switch | Legacy RustFS behaviour kept | rustfs/backlog#2684 entry | Exit condition |
| --- | --- | --- | --- |
| `accept_all_checksum_omissions` | no integrity claim required on any request body; one that is sent is compared | "no checksum required on any operation" (R5) | require checksums as the AWS model does |
| `accept_empty_uploads_without_content_length` | an upload the transport ended empty without `Content-Length` is an empty object | "empty upload without Content-Length stored" | `411 MissingContentLength` (`q-length-0007`) |
| `accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report` | every key up to 1024 bytes without a NUL reaches storage, which judges it | "paths, keys and addressing as legacy" (`key_floor.rs`) | the AWS key floor; only behind a backend that validates keys itself |
| `accept_minio_body_literals` | a bare `Enabled` body on a versioning or object-lock write | "bare `Enabled` body" (R6) | complete XML documents only |
| `accept_mismatched_payload_digests_without_a_body` | a bodyless request's signed digest is not compared | "bodyless signed digest unchecked" | compare the signed digest on every request |
| `address_paths_as_legacy_rustfs` | the path decoded whole before the bucket split, judged before routing, `GET //` as `GET /` | "paths, keys and addressing as legacy" (`addressing.rs`, `legacy_addressing.rs`) | split the path as it arrived; refuse an escaped bucket label |
| `answer_body_refusals_with_legacy_rustfs_sentences` | body refusals worded by code in the API layer's fixed sentences | "digest and short-body failures use one wording" | the core's per-refusal sentences |
| `answer_checksum_failures_with_bad_digest` | every checksum failure is `BadDigest` | "checksum failures answer `BadDigest`" | `InvalidRequest` and `XAmzContentChecksumMismatch` |
| `answer_cors_as_legacy_rustfs` | CORS answered in a layer in front of the stack, every `OPTIONS` before routing, no fallback origins | unregistered (rustfs/gateway#1120) | register; then the core's CORS runtime |
| `answer_credential_refusals_with_legacy_rustfs_sentences` | the two credential refusals in RustFS's words | unregistered (rustfs/gateway#1120) | register; then the core's sentences |
| `answer_denials_with_legacy_rustfs_sentence` | every authorization denial is `Access Denied` | unregistered (rustfs/gateway#1349) | register; then the core's per-stage sentence |
| `answer_head_refusals_without_content_length` | a refused `HEAD` carries no `Content-Length` | unregistered (rustfs/gateway#1120) | register; then the core's framed refusal |
| `answer_header_signatures_as_legacy_rustfs` | header-signature refusals before the credential lookup, naming the field | "signature verification as legacy" (GW-SIG, item 4) | strict SigV4 semantics |
| `answer_heads_as_legacy_rustfs` | `HeadBucket` without a region, a policy write `204`, every restore `200`, a policy read untyped | "response heads and statuses as legacy" | the model's heads, which the core writes by default |
| `answer_not_modified_with_legacy_rustfs_headers` | a `304` with the object's `ETag` and `Last-Modified` on `GET`, none on `HEAD` | "RustFS errors answered as legacy" | the model's `304` headers |
| `answer_presigned_urls_as_legacy_rustfs` | presigned refusals before the credential lookup, naming the parameter | "signature verification as legacy" (GW-SIG, item 5) | strict SigV4 semantics |
| `authorize_header_permissions_as_legacy_rustfs` | a tagging or ACL header asks the base permission only | unregistered (GHSA-3ppv-adjacent) | register; then ask `s3:PutObjectTagging` / `s3:PutObjectAcl` as AWS does |
| `authorize_versions_as_legacy_rustfs` | `HEAD`, tag and ACL reads of a version ask the unversioned action | unregistered (GHSA-3ppv) | register; then the versioned action for every version read |
| `bound_buffered_bodies_as_legacy_rustfs` | buffered bodies read up to 20 MiB with no XML bound below it | unregistered (rustfs/gateway#1173) | register; then the core's ceilings |
| `bound_claimed_route_bodies_as_legacy_rustfs` | a claimed route's body over 1 MiB refused before its access check | unregistered (rustfs/gateway#1173) | register; then the claimed route's own ceiling |
| `clamp_oversized_max_keys` | `max-keys` above 1000 lowered to 1000, not refused | "`max-keys` above 1000 silently lowered" | kept until AWS evidence for the out-of-range answer exists (rustfs/gateway#1093) |
| `drain_unread_request_bodies` (300 s idle) | an unread HTTP/1 body drained behind the answer, then the connection closed | unregistered (rustfs/gateway#1120, rustfs/rustfs#7019) | register; then a bound from RustFS configuration |
| `identify_requests_as_legacy_rustfs` | one UUID in `x-amz-request-id` and `x-request-id`, no `x-amz-id-2`, none in an error document | unregistered (ruling R10) | register; the host hands its identifier over (`HostRequestId`) |
| `ignore_unknown_checksum_algorithms` | a checksum header naming an unknown algorithm is ignored | "unknown-algorithm checksum headers ignored" | refuse unknown algorithms |
| `leave_anonymous_streaming_payloads_undecoded` | an anonymous aws-chunked upload is refused, not decoded | "anonymous aws-chunked upload not decoded" | decode and store, as the generic gateway does |
| `leave_bodies_of_bodyless_operations_unread` | a body on a bodyless operation is never polled | unregistered (rustfs/gateway#1173) | register; then the core default |
| `legacy_rustfs_post_forms` | browser forms read with the legacy grammar | "POST forms parsed with the legacy grammar" (GW-FORM) | RFC 7578 / AWS form semantics |
| `read_aws_chunks_as_legacy_rustfs` | aws-chunked framing with no bound on chunk count or framing share | unregistered (rustfs/gateway#1173) | register; then the core's chunk limits |
| `read_checksum_declarations_as_legacy_rustfs` | a doubled `x-amz-checksum-algorithm` and a two-checksum trailer refused with RustFS's codes | unregistered (rustfs/gateway#1349) | register; then the core's codes |
| `read_checksums_as_legacy_rustfs` | claims read as the storage reader reads them; `x-amz-sdk-checksum-algorithm` not read | "trailer algorithm ignores `x-amz-sdk-checksum-algorithm`" | read the SDK algorithm header as the core does |
| `read_empty_headers_as_absent` | an empty optional header claims nothing | "empty request headers read as absent" | an empty header is a value; an empty expected owner is refused |
| `read_request_documents_as_rustfs` | request documents refused by shape with `MalformedXML` | unregistered (rustfs/gateway#1078) | register; then the core's document reading |
| `refuse_plaintext_customer_keys_before_routing` | a customer key over cleartext refused before routing, copy source included, in RustFS's words | "SSE-C TLS gate" (R11) | the core's gate after routing |
| `refuse_unreadable_date_conditions` | a conditional date in one spelling, the rest refused with `400` | "conditional dates read strictly" (R14) | ignore an unreadable date as RFC 9110 does |
| `refuse_unsigned_amz_headers_before_routing` | a swapped algorithm token, an unreadable SigV4 header or an unsigned `x-amz-*` header refused before routing | "signature verification as legacy" (GW-SIG) | strict SigV4 semantics |
| `refuse_unsized_buffered_bodies_as_legacy_rustfs` | a buffered write RustFS cannot size is refused | unregistered (rustfs/gateway#1173) | register; then the core default |
| `select_operations_as_legacy_rustfs` | `x-id` first, two operation keys ordered by RustFS's table | "paths, keys and addressing as legacy" (`route/legacy_rustfs.rs`) | `Selection::Table`; a query naming two operations refused |
| `sign_base64_payload_digests_as_hex` | a base64 payload digest signed as its hex | "signature verification as legacy" (GW-SIG, item 3) | the value as sent |
| `sign_presigned_payloads_as_unsigned` | every presigned request signed over `UNSIGNED-PAYLOAD` | "presigned payload digest not covered by the signature" | the declared digest covered by the signature |
| `slash_policy(SlashPolicy::RustfsLegacy)` | the leading slashes of a key folded | "paths, keys and addressing as legacy" (`slash.rs`) | AWS slash semantics (persistence-affecting: it renames keys) |
| `url_encode_listings_like_rustfs` | `encoding-type=url` echoed as sent, only some members encoded | "listing echoes `encoding-type`, encodes some members" | the core's encoding |
| `write_responses_as_rustfs` | members in RustFS's order, no line end after the declaration, no namespace on a payload root | unregistered (rustfs/gateway#1078) | register; then the core's layout |
| `framework_governor_rates` (every layer unlimited) | no pre-authentication limit on any layer | "failed signatures and anonymous requests unlimited" | a bounded `credential_lookup` class from RustFS configuration |
| floor: `delegate_anonymous_to_authorizer_after_listing_in_the_posture_report` | every request decided by policy, anonymous ones included | unregistered (ADR-0021) | register; stays while RustFS decides every request by policy |
| floor: `enable_sigv2_presigned_compatibility` | SigV2 presigned URLs accepted | unregistered (rustfs/gateway#913) | register; drop when SigV2 clients are no longer served |
| floor: `with_presigned_expiry_rule(LegacyRustfs)` | `X-Amz-Expires` as a `u32` with `0`, SigV2 `Expires` without the seven-day ceiling | "`X-Amz-Expires` spellings, SigV2 links to 9999" | strict decimal and the seven-day ceiling |
| floor: `admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report` | a presigned URL verified on every standard operation, never on a privileged one | unregistered (rustfs/gateway#1052) | register; per-operation presigned floors |
| floor: `recognize_signatures_as_legacy_rustfs` | a query or form is signed only when it carries the signature; the rest is anonymous | "signature verification as legacy" (GW-SIG, item 9) | strict SigV4 semantics |

The floor's five switches and the governor are not on the `PROFILE_POSTURE` line: `SECURITY_POSTURE`
names the delegation (every non-privileged operation anonymously reachable), the presigned widening
and the SigV2 policy, `PRESIGNED_EXPIRY_POSTURE` names the lifetime rule, and `S3Service::security_posture`
names every lifted governor layer. The recognition switch has no line of its own; the preset's unit
suite pins it against the explicit chain.

### Authenticator half: `SigV4Authenticator::rustfs_profile`

These are not on any posture line: an authenticator is the host's instance, and the builder reports
only what it holds. The preset's unit suite pins the half against the explicit chain, switch for
switch, through the authenticator's own `Debug` posture.

| Switch | Legacy RustFS behaviour kept | rustfs/backlog#2684 entry | Exit condition |
| --- | --- | --- | --- |
| `accept_any_signing_region` | any region of the grammar verified | unregistered (ADR-0023) | a deployment choice; stays |
| `accept_empty_signing_region` | an empty scope region verified | "empty signing region verified" | delete once the replication client signs with a real region |
| `refuse_unreadable_signing_regions_after_verification` | a region outside the grammar refused after the signature, `InvalidRequest` | "region outside the grammar verified, then refused" | refuse before deriving a key |
| `accept_signing_regions_of_any_length` | no ceiling on the region's length | "no region length ceiling" | restore the 64-byte ceiling |
| `verify_paths_as_legacy_rustfs` | the path decoded once for signing, malformed percent literal, the raw candidate by the native rule | unregistered (rustfs/gateway#1314, #1315) | register; then the core's path signing |
| `accept_legacy_rustfs_signing_services` | `s3`, `sts` and `s3tables` verified on every operation, any other service `501` | "signature verification as legacy" (GW-SIG, items 1–2) | the routed operation's own service |
| `answer_credential_scope_refusals_as_legacy_rustfs` | a scope date or region refusal in RustFS's code and words | "signature verification as legacy" (GW-SIG, item 6) | strict SigV4 semantics |
| `read_signed_headers_as_legacy_rustfs` | `SignedHeaders` read verbatim; a list that does not cover what it must refused in RustFS's words | "signature verification as legacy" (GW-SIG, items 7–8) | strict SigV4 semantics |

## Reading the posture

An assembly running the profile writes six lines at start-up, in this order, and
`S3Service::startup_posture` returns the first five as one text:

1. `SECURITY_POSTURE` — every registered operation under `anonymous_reachable_ops` and
   `presigned_allowed_ops`, `sigv2_policy=HeaderAndPresigned`;
2. `DIALECT_POSTURE` — whatever dialects the host installed; the launcher installs none;
3. `PRESIGNED_EXPIRY_POSTURE rule=legacy-rustfs`;
4. `NAMING_POSTURE slash_policy=rustfs-legacy … key_floor=rustfs-legacy … path_split=rustfs-legacy`;
5. `PROFILE_POSTURE switches=[…]` — the 42 builder- and router-held readings above, sorted;
6. the `SecurityPosture` line a host prints itself — `per-IP bucket: unlimited` and every
   pre-authentication layer under `unlimited pre-authentication layers`.

A line that reads otherwise is an assembly that is not running the profile whole.
