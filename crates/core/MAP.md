# rustfs-gateway-core crate map

Agent entry point for operations, routing, codecs, authorization state and handler registration.

| File | Responsibility | Read it when |
|---|---|---|
| `src/contracts.rs` | Closed runtime vocabulary plus generated typed contract data. | A shared runtime module must consume a protected protocol decision. |
| `src/contracts/precondition.rs` | Closed conditional and byte-range runtime policy types. | A precondition contract needs a new typed consumer input. |
| `src/contracts/cors.rs` | Closed bucket-CORS runtime policy types and predicates. | A CORS parser, matcher or response path must consume a protected decision. |
| `src/contracts/select_restore.rs` | Closed select, event-stream and restore runtime policy types. | A select/restore protocol decision needs a typed runtime consumer. |
| `src/lib.rs` | Module wiring and public re-exports. | Start here for a core task. |
| `src/op.rs` | Operation identity, origin and authorization requirements. | Add an operation or inspect standard-name rules. |
| `src/ops/*.rs` | Exactly one `impl Operation` per AWS operation. | Change one operation's static contract. |
| `src/ops/delete_object_annotation.rs` | Reserves annotation deletion independently of destructive object deletion. | An annotation DELETE routes to DeleteObject or declares the wrong authorization floor. |
| `src/ops/get_object_annotation.rs` | Reserves a named annotation read independently of the parent object body. | A named annotation GET routes to GetObject or declares the wrong authorization floor. |
| `src/ops/put_object_annotation.rs` | Reserves annotation payload writes independently of parent object replacement. | An annotation PUT routes to PutObject or loses its required streaming body. |
| `src/ops/get_object_torrent.rs` | Reserves a torrent descriptor read independently of the parent object body. | A torrent GET routes to GetObject or declares the wrong authorization floor. |
| `src/ops/get_bucket_ownership_controls.rs` | Reserves an ownership-controls read independently of bucket object listing. | An ownership-controls GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_abac.rs` | Reserves an ABAC status read independently of bucket object listing. | An ABAC GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_analytics_configuration.rs` | Reserves one named analytics-configuration read independently of bucket object listing. | An id-bearing analytics GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_intelligent_tiering_configuration.rs` | Reserves one named tiering-configuration read independently of bucket object listing. | An id-bearing intelligent-tiering GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_inventory_configuration.rs` | Reserves one named inventory-configuration read independently of bucket object listing. | An id-bearing inventory GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_metadata_configuration.rs` | Reserves the V2 S3 Metadata read independently of bucket object listing. | A metadata-configuration GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_metadata_table_configuration.rs` | Reserves the legacy S3 Metadata table read independently of bucket object listing. | A metadata-table GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/get_bucket_metrics_configuration.rs` | Reserves one named metrics-configuration read independently of bucket object listing. | An id-bearing metrics GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/list_bucket_intelligent_tiering_configurations.rs` | Reserves tiering-configuration listing independently of bucket object listing. | A bare intelligent-tiering GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/list_bucket_inventory_configurations.rs` | Reserves inventory-configuration listing independently of bucket object listing. | A bare inventory GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/list_bucket_metrics_configurations.rs` | Reserves metrics-configuration listing independently of bucket object listing. | A bare metrics GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/list_directory_buckets.rs` | Reserves directory-bucket listing independently of ordinary account bucket listing. | An S3 Express control GET routes to ListBuckets or uses the S3 signature floor. |
| `src/ops/list_object_annotations.rs` | Reserves annotation metadata listing independently of the parent object body. | An annotation listing routes to GetObject or declares the wrong authorization floor. |
| `src/ops/list_bucket_analytics_configurations.rs` | Reserves analytics-configuration listing independently of bucket object listing. | A bare analytics GET routes to ListObjects or declares the wrong authorization floor. |
| `src/ops/rename_object.rs` | Reserves the directory-bucket rename contract independently of backend registration. | A rename request routes to PutObject or declares the wrong authorization floor. |
| `src/ops/update_object_encryption.rs` | Reserves an object encryption update independently of destructive object replacement. | An encryption update routes to PutObject or declares the wrong authorization floor. |
| `src/ops/shared/` | Explicit cross-operation protocol logic. | A list/copy/conditional/ACL/checksum rule affects several operations. |
| `src/ops/shared/rule_filter.rs` | The one rule `<Filter>`/`<And>` grammar lifecycle and replication both call, with each family's member set. | Either family's Filter or And acceptance changes. |
| `src/ops/shared/trailer_checksum.rs` | `request_checksum`: the checksum a streaming body claimed, from its header or from the trailer it ended with, under the header decoder's field rule. | A backend stores a part or object checksum, or a trailer-carried checksum goes missing. |
| `src/route/mod.rs` | Routing module map and pre-auth invariant. | Start a routing task. |
| `src/route/selector.rs` | Route predicates and entries. | Add or interpret a predicate. |
| `src/route/lattice.rs` | Selector overlap/refinement decision. | A conflict or shadowing decision is wrong. |
| `src/route/table.rs` | Ordered table construction and resolution. | A request selects the wrong operation. |
| `src/route/claim.rs` | A dialect's path-prefix claims, path templates and their typed values (ADR-0024). | A claim or template refuses, matches or extracts the wrong thing. |
| `src/route/claimed.rs` | Claimed rows, and the table the router asks before the S3 table. | A claimed request reaches the wrong row, or reaches S3. |
| `src/route/shadowing.rs` | Declaration types; mounts the generated record from `model/overlays/route.toml`. | A route intentionally stands before another. |
| `src/route/compiled.rs` | Fast lookup equivalent to the readable table. | Routing performance or equivalence fails. |
| `src/route/explain.rs` | Route explanation data. | `cargo xtask route explain` omits a reason. |
| `src/codec/mod.rs` | Per-operation wire codec contract. | Add a decode/encode binding. |
| `src/codec/view.rs` | Normalized request metadata view. | Headers, query or path labels decode wrongly. |
| `src/codec/legacy_path.rs` | Legacy RustFS's path split (#1115): the whole path decoded once, the bucket ended at the first decoded `/`, and the refusals it makes before routing. | A RustFS-profile request reaches the wrong bucket, key or refusal. |
| `src/codec/value.rs` | IR scalar conversions and strict wire forms. | A scalar is accepted, rejected or rendered wrongly. |
| `src/codec/rustfs_listing.rs` | Legacy RustFS's `encoding-type=url` rule for a listing under the RustFS profile: which members, `/` literal, the echo. | A RustFS-profile listing encodes the wrong members or echoes the wrong value. |
| `src/codec/response.rs` | Encoded response/body allowance. | A response has the wrong body/status shape. |
| `src/codec/extra_headers.rs` | A handler's extra response headers and the gateway-owned names they may not use (rustfs/gateway#1018). | A backend header is refused, dropped or allowed to override the encoder. |
| `src/codec/tests/metadata_and_url.rs` | Metadata symmetry and forced listing-encoding regressions. | RFC 2047 or `encoding-type=url` behavior changes. |
| `src/authz.rs` | Authorization type-state and derived resources. | A handler can run without the intended proof. |
| `src/authz/rule.rs` | ADR-0025's action rules (any-of, all-of, fail-closed combination) and subject rules, and ADR-0026's set rule (strict single and set extraction into `Subjects`). | Several actions or named accounts decide an operation. |
| `src/authz/plan.rs` | The route-stage questions for a requirement and its subjects (one per action and account, plus every account's broader action), and their fail-closed settling. | A set, or every account, is authorised wrongly. |
| `src/authz/query.rs` | The strict one-parameter query reader subjects and a query-bound bucket share. | A query parameter authorisation depends on is read twice or leniently. |
| `src/registry/reject_rule_tests.rs` | Every registration refusal of an action or subject rule, and the overlay reading the rendered rule. | A rule is refused or admitted wrongly. |
| `src/cancellation.rs` | Runtime-independent handler cancellation signal and waiter registry. | A handler deadline or rollback signal is lost or amplified. |
| `src/request_context.rs` | The read-only handler request context (ADR-0022): principal, verified scope, routed target, raw target and header lines, transport values, and the explicitly named caller secret. | A handler needs to know who called, or a context value is wrong or leaks. |
| `src/request_context/tests.rs` | Unit tests: no context for a rejected verdict, nothing for an anonymous one, every line copied, `Debug` redaction. | A context unit guarantee changes. |
| `src/committed.rs` | Typed frozen response heads and statusless detached work for the generated deferred-operation set. | A permitted operation, early header, or committed outcome is wrong. |
| `src/handler.rs` | Typed handler request/response contracts, including the carried SSE proof. | Implement a backend or represent a committed failure. |
| `src/static_dispatch.rs` | Sealed generic codec and concrete-handler entry. | Build or audit the monomorphic facade path. |
| `src/dialect/error.rs` | `DialectError`, every dialect refusal as one enum. | A dialect refusal's wording or variant changes. |
| `src/dialect/claimed.rs` | Operations a dialect serves inside its own claims: rows, aliases, the overlay cross-check. | A claimed route is refused, or its alias is not reviewed. |
| `src/registry/` | Handler/codec registration and erasure. | Registration, completeness or dynamic dispatch fails. |
| `src/dispatch.rs` | Route, registration and parameter refusal order. | A request fails in the wrong stage. |
| `src/error.rs` | Closed pre-authentication errors. | A refusal before authentication has the wrong status. |
| `src/error_resolution.rs` | Closed contextual error resolution and body policy. | A contextual refusal has the wrong code, status, extras or body policy. |
| `src/error_resolution/validate.rs` | Admission checks for an ordinary refusal: code, message and detail bounds, contextual codes, and which headers and details a code may carry. | A handler refusal is admitted or refused bare when it should not be. |
| `src/fault.rs` | Closed error headers/details. | An error document needs a reviewed field. |
| `src/cors/` | CORS rule and response primitives. | CORS semantics change. |
| `src/sse/` | Server-side encryption proof, bounded KMS context JSON validation and rejection types. | SSE headers or key handling change. |
| `tests/route_table.rs` | Route-table positive/negative matrix. | Any route row changes. |
| `tests/selector_required_params.rs` | c-param-1003 on `GetBucketAnalyticsConfiguration`: `id` routes to the read (listing without it) and the read decoded without it is a static 400. | A parameter is both a route discriminator and a required member. |
| `tests/dialect_claims.rs` | What a claim captures, templates, aliases, typed values, the secret opt-in default. | A claim captures too much or too little. |
| `tests/dialect_claims_refusals.rs` | Every claim, template and claimed-row refusal, one variant each. | A claimed-route refusal changes. |
| `tests/route_sizes.rs` | Independent compile-time size ceiling for the copied hot-path bucket. | The compiled router's bucket layout changes. |
| `benches/route.rs` | Allocation gate and non-blocking timing record for compiled route lookup. | Routing hot-path cost changes. |
| `benches/codec.rs` | Allocation ceilings and timing records for ListObjectsV2 encode, DeleteObjects decode and the GetObject head. | A codec change moves an allocation ceiling. |
| `tests/params_and_dispatch.rs` | Dispatch and required-parameter matrix. | Registry or dispatch changes. |
| `tests/pre_auth_errors.rs` | Static pre-authentication constructors and allowed statuses. | A pre-authentication constructor or status changes. |
| `tests/configuration_error_declarations.rs` | Static unconfigured-error declarations for operation triples. | A configuration operation's missing-state error changes. |
| `tests/registration.rs` | Registration rejection matrix. | Handler registration changes. |
| `tests/static_dispatch.rs` | Static dispatch order and identity mismatch. | Change the monomorphic core boundary. |
| `tests/precondition_range.rs` | Conditional/range behavior matrix. | Precondition logic changes. |
| `tests/range_part_table.rs` | Part-number window resolution and its refusals. | A `partNumber` read serves the wrong bytes or the wrong count. |
| `tests/error_resolution.rs` | P1-04 contextual error outcome matrix. | Change error masking, status, extras or body suppression. |
| `tests/rule_filter_boundaries.rs` | Filter boundaries both consumers of the shared grammar still answer, side by side. | A lifecycle or replication Filter refusal changes. |
| `tests/security_request_policy.rs` | Unknown-element refusal for every security configuration PUT (allow-registered write policy). | A security PUT starts accepting, or stops refusing, an unregistered element. |
| `tests/purity_guard.rs` | Source-shape guards for pre-auth code. | Add public/core routing code. |
| `tests/xml_parse_replay.rs` | Replays `fuzz/seeds/xml_parse/` and 40,000 fixed-seed samples through the `xml_parse` property over `rustfs-gateway-xml`'s bounded reader. | Change an XML ceiling or refusal, or add a minimised fuzz regression seed. |
| `tests/select_records_framing.rs` | `EventSequence::records` splitting a payload past the one-message ceiling into consecutive frames, still refused out of phase. | Change `EventSequence::records` or `MAX_PAYLOAD_BYTES`. |
| `tests/event_stream_frame_replay.rs` | Replays `fuzz/seeds/event_stream_frame/`, every four-call sequence script and fixed-seed scripts through the `event_stream_frame` property: production framing and `EventSequence` held to an independent CRC, frame reader and sequence model. | Change event-stream framing, a header or payload ceiling, or the sequence order. |
| `tests/policy_json_replay.rs` | Replays `fuzz/seeds/policy_json/` and 20,000 fixed-seed samples through the `policy_json` property: the `PutBucketPolicy` codec and `validate_policy` held to a strict duplicate-aware JSON reader. | Change a bucket policy check or ceiling, or add a minimised fuzz regression seed. |
| `tests/restore_header_replay.rs` | Replays the Restore header grammar and calendar boundaries fuzz property on stable. | Restore header parsing or formatting changes. |
| `tests/golden/route-table.txt` | Protected ordered route table. | Never edit without the Breaking Change process. |
