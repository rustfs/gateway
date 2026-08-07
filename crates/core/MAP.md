# rustfs-gateway-core — crate map

Which S3 operation a request names, what that operation requires of it, whether this backend
handles it, and how it is called. P4-01 landed the ordered route table and its build-time overlap
decision, P4-02 split parameter validation from routing, P4-03 added the compiled lookup form, and
P4-06 added the operation trait, the per-operation handler, and the registry that erases the backend
type — and, with the generated codecs, the operation type too: one `register_handler::<O, B>` call
installs the decoder, the handler and the encoder in a single entry, which is what lets a layer
holding only an operation *name* turn wire bytes into an answer. Nothing on the routing path is
`async`, nothing there holds a store, and nothing there can say a word about a request that is not a
compile-time constant — routing runs before the signature is verified. `src/registry/handlers.rs` is
the one file that awaits, and it runs after the floor has admitted the request.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, re-exports, the three properties in full | First stop; you can often stop here |
| `src/route/mod.rs` | The map of the routing module and the pre-auth invariant | Before touching anything under `route/` |
| `src/route/selector.rs` | `Predicate` (ten variants), `TargetKind`/`HostClass`/`ArnForm`, `RouteSelector`, `RouteEntry`, and evaluation | You are adding a predicate or asking what one means |
| `src/route/lattice.rs` | Normalisation into constraints, the meet, refinement, the witness | You are touching the conflict decision |
| `src/route/shape.rs` | `RequestShape`: the concrete request a conflict is reported with | Rarely |
| `src/route/table.rs` | `RouteTable::build` and its refusals, first-match `resolve`, the golden rendering | You changed a table or hit a build error |
| `src/route/shadowing.rs` | `ShadowingDecl`, `ShadowingPolicy`, and the compile-time join of the table's two halves into `PROVISIONAL_SHADOWING` | The build asks you for a declaration |
| `src/route/shadowing_bucket.rs`, `src/route/shadowing_object.rs` | The declarations themselves, split along the one seam the table has — which target the overlapping selectors address — when it outgrew the 800-line ceiling. Eighty bucket pairs, forty object ones | You are adding a declaration: pick the half by the target, and the join needs no edit |
| `src/route/evidence.rs` | The AWS reference URL constants the shadowing declarations cite, split out when the table outgrew the file ceiling | You are adding a declaration for an operation with no constant yet |
| `src/route/mask.rs` | Routing query keys → one bit each, derived from the table itself | You hit the 64-key ceiling |
| `src/route/compiled.rs` | `CompiledRouter`: `method × target` buckets, mask rules, the empty-mask shortcut | You are changing lookup performance |
| `src/route/explain.rs` | `Explanation`: what won, what it hid, and why | You are building `route explain` |
| `src/route/generated.rs` | `RouteRow`/`RoutePredicate` and the parse of `generated/routes.rs` | Codegen changed the emitter |
| `src/op.rs` | `Operation`, `OperationOrigin` and its sealed token, `AuthRequirement`, `HasOperation`, the standard-name set | You are adding an operation, or asking what makes one standard |
| `src/codec/mod.rs` | `OperationCodec`, and the orphan-rule reason the generated codecs are mounted here rather than in `rustfs-gateway-types` | You are adding an operation family, or asking where a wire binding lives |
| `src/codec/view.rs` | `MetaView` — the request head a decoder reads, with the URI labels split and percent-decoded **exactly once** and repeated header field lines joined as RFC 9110 §5.3 defines them — and `RequestBody`'s three shapes | You are decoding a path label, asking what a header sent twice decodes to, or asking why a decoder cannot aggregate a streaming body |
| `src/codec/response.rs` | `EncodedResponse`, `ResponseBody`, the `response-*` override table, and `body_allowance` — the one copy of the RFC 9110 body **decision**, which the facade enforces over its own response type too | A response carries a body it should not, or an override did not apply |
| `src/codec/value.rs` | One function per IR scalar, in each direction, plus the one-checksum-header rule and its head-only entry point `refuse_contradictory_checksums` (the same function, reached by an assembly that has a request head and no operation input yet, so the contradiction is answered above the body read), the bounded-integer refusal, the two wire-form refusals (entity tag, server-minted cursor), `MAX_TOKEN_LEN` — the cursor ceiling `crates/http`'s query budget is derived to stay above — the one **tolerant** read (`DateCondition` / `date_condition`, the header RFC 9110 says to ignore), the `httpChecksumRequired` body guard, and the decode-path placeholder exit | A wire value is parsed or rendered wrongly, a header must be ignored rather than refused, or a request is refused before its body is read |
| `src/codec/tests.rs` | 34 tests over the object family: what the generated codecs do to bytes, including the bounded scalars and the required integrity check | You changed an emitter or a conversion |
| `src/ops/*.rs` | One AWS operation per file: spec, floor, `impl Operation`, `impl HasOperation` | You are adding an operation — copy the nearest one |
| `src/ops/get_object_attributes.rs` | The attributes read. Present with no backend behind it anywhere in this workspace, on purpose: without its row `?attributes` is claimed by `GetObject` and answered with the object's bytes | You are asking why an operation nobody handles has a module |
| `src/ops/get_object_tagging.rs`, `src/ops/put_object_tagging.rs`, `src/ops/delete_object_tagging.rs` | The object `?tagging` band, 480/490/500. Here for the same reason as the attributes read and with worse consequences: without their rows the write stored the tagging document **as** the object and the delete removed **the object** | You are asking why three operations no backend in this workspace handles have modules |
| `src/ops/get_bucket_cors.rs`, `src/ops/put_bucket_cors.rs`, `src/ops/delete_bucket_cors.rs` | The `?cors` band, 310/320/330 — configuration codec only; preflight is a separately designed pre-auth stage. The GET row retires the `GetBucketCors -> ListObjects` debt-register line; the unconfigured read is the operation-specific `NoSuchCORSConfiguration` 404 | You are adding a bucket subresource triple — this is the template, `not_configured_error` included |
| `src/ops/get_bucket_tagging.rs`, `src/ops/put_bucket_tagging.rs`, `src/ops/delete_bucket_tagging.rs` | The bucket `?tagging` band, 340/350/360, behind the `?cors` band. `GetBucketTagging` declares `NoSuchTagSet` as its `not_configured_error` — the opposite of the object read's 200-with-empty-set — and both scopes validate through `shared/tagging.rs` | You are adding the next bucket subresource triple — copy either this or the CORS one |
| `src/ops/create_bucket.rs`, `src/ops/delete_bucket.rs`, `src/ops/head_bucket.rs` | The bucket lifecycle band, 710/720/730. Each selector pins the **absence** of every bucket subresource key under its method — served (`cors`, `tagging`) and deferred alike — which keeps the lifecycle rows provably disjoint from the subresource bands and is what stops `PUT /b?acl` from being served as a creation and `DELETE /b?policy` from deleting the bucket | You are asking why three bucket rows carry two dozen `QueryAbsent` predicates each |
| `src/ops/shared/cors.rs` | The CORS document's semantic rules — closed method set, wildcard budgets, the 100-rule cap, `ID`/`MaxAgeSeconds` bounds — as `validate_cors` and `CorsRejection`, exported through the facade so every backend refuses the same documents with the same codes | A CORS document was accepted or refused wrongly, or you are the preflight task looking for what a stored document is guaranteed to satisfy |
| `src/ops/get_bucket_lifecycle_configuration.rs`, `src/ops/put_bucket_lifecycle_configuration.rs`, `src/ops/delete_bucket_lifecycle.rs` | The `?lifecycle` band, 370/380/390 — configuration codec only; rule evaluation is the storage backend's scanner. The GET row retires the `GetBucketLifecycleConfiguration -> ListObjects` debt-register line; the unconfigured read is the operation-specific `NoSuchLifecycleConfiguration` 404; the delete keeps the model's 2012 name | You are adding the next subresource triple beside an existing one — this band shows the cross-band shadowing pairs |
| `src/ops/shared/lifecycle.rs` | The lifecycle document's semantic rules — the filter's one-child grammar and the `<And>` floor, the Filter-or-Prefix scope, the expiration mutex, the midnight rule, the 1000-rule cap, `ID` bounds and uniqueness — as `validate_lifecycle` and `LifecycleRejection`, deliberately no stricter than AWS's documented refusals because stored configurations are re-parsed by every release | A lifecycle document was accepted or refused wrongly, or you are deciding whether a new check belongs in the validator or in leniency |
| `src/ops/get_bucket_encryption.rs`, `src/ops/put_bucket_encryption.rs`, `src/ops/delete_bucket_encryption.rs` | The `?encryption` band, 391/392/393 — configuration codec only; applying the default and every SSE header contract is P6-06. Packed after `?lifecycle` because the tens-aligned slots before the multipart band are full; the GET row retires the `GetBucketEncryption -> ListObjects` debt-register line; the unconfigured read is the operation-specific `ServerSideEncryptionConfigurationNotFoundError` 404 | You are adding a subresource triple when the 300-band is out of tens-aligned slots |
| `src/ops/get_object_lock_configuration.rs`, `src/ops/put_object_lock_configuration.rs` | The bucket `?object-lock` pair, 397/398 — a **pair**, not a triple: the model defines no delete, because object lock once enabled has no wire spelling for "off". Configuration codec only; lock enforcement is later work. The GET row retires the `GetObjectLockConfiguration -> ListObjects` debt-register line, and its unconfigured read is the bucket-level `ObjectLockConfigurationNotFoundError` 404 | You are adding a subresource family with no delete, or asking where the bucket band ends |
| `src/ops/get_object_retention.rs`, `src/ops/put_object_retention.rs`, `src/ops/get_object_legal_hold.rs`, `src/ops/put_object_legal_hold.rs` | The object `?retention` and `?legal-hold` rows, 510/520/530/540, beside the object `?tagging` band and for the same reason with a compliance meaning on top: without them the reads answered the object's bytes and the writes stored the document **as** the object, destroying the file they were protecting. Their unconfigured reads answer the *object-level* `NoSuchObjectLockConfiguration`, a different code from the bucket read's | You are asking why the two 404s in one family differ, or adding an object subresource after the tagging band |
| `src/ops/shared/object_lock.rs` | The three lock documents' semantic rules — the closed `Mode`, `Status` and `ObjectLockEnabled` sets, the `Days`/`Years` mutex and its ≥1 floor, and the future-only `RetainUntilDate` measured against a clock the **caller** passes — as `validate_lock_configuration`, `validate_retention`, `validate_legal_hold` and `ObjectLockRejection`. The closed sets are two comparisons rather than `is_known()`, because the generated `Mode` and `Status` enums are shared by wire name with other families | A lock document was accepted or refused wrongly, or you are the enforcement task looking for what a stored document is guaranteed to satisfy |
| `src/ops/shared/encryption.rs` | The default-encryption document's semantic rules — the closed `SSEAlgorithm` set and the KMS-key-id/algorithm agreement — as `validate_encryption` and `EncryptionRejection`, with constant reasons that never repeat the sensitive key id | An encryption document was accepted or refused wrongly, or a refusal message is suspected of echoing a key id |
| `src/ops/get_bucket_replication.rs`, `src/ops/put_bucket_replication.rs`, `src/ops/delete_bucket_replication.rs` | The `?replication` band, 394/395/396 — configuration codec only; rule evaluation, cross-site transfer and the `x-amz-replication-status` header (P5-01) are the engine's. The GET row retires the `GetBucketReplication -> ListObjects` debt-register line; the unconfigured read is `ReplicationConfigurationNotFoundError`, one of the few codes whose literal ends in `Error`; the write passes `x-amz-bucket-object-lock-token` through unread | You are adding the sixth subresource triple, or you need the band that packs directly behind `?encryption` |
| `src/ops/shared/replication.rs` | The replication document's semantic rules — the V1/V2 schema exclusivity (`classify_rule`, `RuleShape`), the filter's one-child grammar and `<And>` floor, the 1000-rule cap, `ID` bounds and uniqueness — as `validate_replication` and `ReplicationRejection`. The leniencies matter more than the refusals: this is the one configuration RustFS parses **fail-closed**, so a stricter decoder makes buckets unusable rather than switching a feature off | A replication document was accepted or refused wrongly, or you are deciding whether a new check belongs in the validator or in a documented leniency |
| `src/ops/shared/bucket_region.rs` | Where `x-amz-bucket-region` must appear, and the two redirects that carry it: the 301 for a bucket in another region and the 307 shape whose trigger this crate does not own | A redirect is missing the header an SDK needs to complete it |
| `src/ops/shared/location_constraint.rs` | `LocationConstraint` parsing: the `EU` alias, the empty-element rule, the us-east-1 omission rule, and the strict match against the one `RegionSet` the signature scope also reads. `RegionMatchPolicy` is the configuration item | A creation was accepted or refused for the wrong region |
| `src/ops/shared/copy_source.rs` | `x-amz-copy-source`: the three grammars, the split-before-decode order, the source-authorization type state, the self-copy classification and the stricter copy-range rule | You are touching anything a copy reads from, or asking why the source's bucket cannot be read without a proof |
| `src/ops/shared/etag.rs` | Which RFC 9110 comparison each conditional entity-tag header uses, and how its value is read | An entity-tag condition matched when it should not have, or the other way round |
| `src/ops/shared/tagging.rs` | What a tag set may be, once for its two request channels: the `x-amz-tagging` header grammar, the per-scope count ceilings (10 object / 50 bucket), the 128/256-character limits, the documented character set, and the duplicate-key refusal | A tag was accepted or refused wrongly on either channel, or a tagging error carries the wrong code |
| `src/ops/shared/precondition.rs` | The fixed precondition order, the two places S3 departs from RFC 9110, the 200/206/416 range decision, and six inline tests for the one validator shape `tests/precondition_range.rs` never builds — a representation that exists with no entity tag, where `*` must still hold | You are wiring a conditional or ranged operation, or a 304/412/416 came out wrong |
| `src/handler.rs` | `Handler<O>`, `Req`, `Resp`, `Answer` / `CommitOutcome` / `CommitWork` (the "committed, then failed" shape), `HandlerError` (code, message, response headers, document elements), `BoxFuture` | You are implementing a backend, a refusal needs a header or an extra element, or an operation has to flush its status before it knows its outcome |
| `src/fault.rs` | `ErrorHeader` and `ErrorDetail`: the two **closed sets** a refusal may add to itself, the canonical `ELEMENT_ORDER`, and the two AWS-pinned messages | You need a header or an element on an error response, or you are asking why it is not a `HeaderMap` |
| `src/registry/mod.rs` | `OperationSpec`, `RequiredParam`, `check_required`, `Registry`, `WireEntry` — and `register_handler`, the one call that installs a handler and a codec together | You are adding a required parameter, or looking an operation up by name |
| `src/registry/reject.rs` | `RegistryError` and the seven rules an operation passes before it registers | A registration was refused |
| `src/registry/handlers.rs` | The erasure closure, `HandlerTable` (handler **and** codec in one entry), `Invocation` — the only file here that awaits | You are wiring the pipeline to the handlers |
| `src/registry/codecs.rs` | `ErasedDecode`, `ErasedEncode`, `ErasedCodec` — where the operation type disappears, so a `&str` reaches `decode` and `encode` | You are wiring the pipeline to the codecs |
| `src/registry/opset.rs` | `OperationSet`, `MissingHandlers` and its one-line message | You are asserting completeness |
| `src/registry/builder.rs` | `RouterBuilder`: `handle`, `route`, `require`, `build`, and `BuildError` | You are assembling a service |
| `src/error.rs` | `PreAuthError` and the closed pre-authentication status set | You are raising an error before authn |
| `src/dispatch.rs` | `Router`: route, then registration, then parameters — three failures, not one | You are wiring the pipeline |
| `tests/route_table.rs` | 22 positive / 78 negative — every routing and build-refusal case, plus the attributes row, the `?cors`, `?lifecycle`, `?encryption`, `?replication` and both `?tagging` bands (object and bucket), the `?object-lock` pair and the `?retention` / `?legal-hold` rows, and the bucket lifecycle band whose `QueryAbsent` predicates are checked one subresource key at a time | You changed `table.rs` or `lattice.rs` |
| `tests/params_and_dispatch.rs` | 10 positive / 25 negative — the 400-not-501 rule, the error properties, the routed-but-unhandled `501` over the generated table for `?attributes`, the `?cors`, `?lifecycle`, `?encryption`, `?replication` and `?object-lock` bands, all six `?tagging` requests, the four `?retention` / `?legal-hold` requests and all three bucket lifecycle methods, the declared `NoSuchTagSet` unconfigured answer, the replication read's own and the object-lock family's two distinct ones, and the deferred bucket subresource request that must reach no route at all | You changed `registry.rs` or `error.rs` |
| `tests/hot_path.rs` | 7 positive / 10 negative — cost, the key ceiling, and the differential generator | You changed `compiled.rs` or `mask.rs` |
| `tests/golden.rs` + `tests/golden/route-table.txt` | The whole table as text, so a routing change shows up in a diff | Codegen changed |
| `tests/registration.rs` | 7 positive / 17 negative — the registration rules, erasure, `require`, the 501 | You changed anything under `registry/` |
| `tests/codec_binding.rs` | 3 positive / 6 negative — a name reaching decode, handler and encode; the uncoded escape hatch; what a duplicate cannot undo | You changed `registry/codecs.rs` or the registration signature |
| `tests/purity_guard.rs` | 12 source guards: no `async` off the allowance list, no store, no leaked message, one `Box::pin`, file shape | You added a file or a public method |
| `tests/precondition_range.rs` | 17 positive / 27 negative plus three properties — every conditional outcome, both S3 deviations, and the range boundaries | You changed anything under `ops/shared/` |
| `tests/tolerant_conditions.rs` | 3 positive / 9 negative — the two date conditions on both read operations are ignored when unreadable, the members beside them stay strict, and the collapse to `None` happens in one named place | You changed `date_condition`, or a `header_tolerance` quirk reference |
| `tests/tagging_contract.rs` | 8 positive / 17 negative plus one property — the packed-header grammar, both scope ceilings, the character set, and which code each refusal carries | You changed anything in `ops/shared/tagging.rs` |
| `tests/limit_layering.rs` | 1 positive / 5 negative — the only place in the tree that can see both `MAX_TOKEN_LEN` and `crates/http`'s query budget, so it is where the inequality between them is asserted | You changed either ceiling, or `c-list-0030` moved |

## Shape decisions worth not re-litigating

- **Ordered, not disjoint.** `GET /b?acl&tagging` is a request AWS answers. A disjoint table needs
  quadratically many `Absent` predicates that every new subresource invalidates, and the SDKs'
  `?x-id=` would make any "unknown key is ambiguous" rule reject ordinary traffic. Overlap *within*
  one precedence stays fatal: there the winner is sort order.
- **Overlap is a decision, not a comparison.** `GET /b?acl` and `GET /b` are unequal, share no key,
  and one is dead. Selectors normalise into constraints over independent dimensions; two overlap
  exactly when their meet is non-empty. The meet is then materialised into a request and run back
  through the ordinary matcher — a lattice bug cannot report "no conflict", it reports an
  inconsistency.
- **Requiredness is not a routing predicate.** `?analytics` without `id` is a `400` from an
  operation already chosen. As a predicate it would be a `501`, and clients disable features on a
  `501`.
- **Two `501`s, two messages.** "No route" means the vhost domain is probably unconfigured; "not
  registered" means write a handler. One string for both hides which happened.
- **Pre-auth messages are `&'static str`.** Not a review rule — a type. `format!` does not
  typecheck, and `tests/purity_guard.rs` refuses `Box::leak`, which is the only laundering route.
- **The bit table has no second source.** Keys are derived from the route table's own selectors, so
  the classic "hand-written keyword list drifts from the table" failure has nowhere to happen. Over
  64 keys is a hard compile error naming the key that did not fit, never a truncation.
- **The shortcut answers one context.** Zero mask, standard endpoint, no ARN. Rules that need an
  ARN or a different endpoint are skipped at compile time (so one access-point entry does not cost
  every object read its fast path); a rule with any residual predicate disables the shortcut for
  that bucket entirely (so `POST /bucket` is never answered without looking at `content-type`).
- **The backend type is erased at registration, and the operation type is not.** A registry entry
  has to call `B::call`, so it has to know `B` — which is why link-time collection cannot work
  (measured `error[E0117]`, ADR-0003). Erasing `B` in a closure keeps `Router` non-generic, which is
  what lets one process hold two routers over two backends.
- **The codec is erased in the same call, and lives in the same entry.** `OperationCodec::decode`
  and `encode` are generic per operation; every layer above the registry holds a `&str`.
  `register_handler::<O, B>` is the only place that has the type and the name at once, so the bridge
  is built there — and into one `HandlerTable` entry, because two maps keyed by the same name are
  two maps that can disagree. There is no method that attaches a codec to an entry that already
  exists, and a duplicate registration cannot strip one off.
- **`register_handler` requires `O: OperationCodec`; the codec-less path is spelled out.** The
  default is the one that can actually answer a request. An operation whose wire form this crate does
  not define registers through `register_handler_without_codec` /
  `RouterBuilder::handle_without_codec`, which `grep` finds and which
  `HandlerTable::names_without_codec` reports afterwards — so a facade refuses to start rather than
  routing an operation nothing can read.
- **Completeness is a run-time assertion, not a bundle trait.** A bundle supertrait produced 73
  `E0277` errors for one missing implementation and was not dyn compatible.
  `require(&OperationSet)` produces one sentence: `backend is missing handlers for: A, B (2 of 73)`.
- **An operation with no authorisation action cannot be registered.** That is the structural form of
  rustfs/rustfs#4845 — there is no registration path on which the question can be skipped.
- **A third party cannot claim to be an AWS operation.** `OperationOrigin::Standard` carries a token
  whose field is private to this crate, so the namespaced-name rule cannot be opted out of.
- **The readable table is not deleted.** A fast implementation of a pre-auth security decision is
  only allowed to exist while something proves it agrees with the one a person can read.
- **Binary search, not `phf`.** `phf` is not a workspace dependency and this task may not add one.
  Sixty-four short sorted keys is six comparisons and no build script.

## Open for maintainer review

- **The commit seam is wired end to end and nothing in this repository exercises it against the
  corpus.** `Resp::commit` and the facade's `commit` module answer `c-mpu-0001`, `c-mpu-0038`,
  `c-mpu-0040` and `c-copy-0038` in principle; none of the four can go green, because the only
  backend is `crates/conformance/src/fixture.rs` (which would have to call `Resp::commit` for
  `CompleteMultipartUpload` and `CopyObject`) and the only transport is
  `crates/conformance/src/inprocess.rs` (which reports `Outcome::Response`, `stream_termination:
  None` and `body_bytes_before_error: None` unconditionally, so `expect.kind = "stream_error"` can
  never be satisfied). `c-mpu-0040` needs a third thing again: a backend that stops making progress
  and a transport that can observe an abrupt close.
- **`c-mpu-0001` and `c-mpu-0038` disagree about the committed prologue.** `c-mpu-0001` and
  `c-copy-0038` both pin `body_bytes_before_error = 39` and name those bytes "the XML declaration and
  its newline"; `c-mpu-0038` asserts `declaration = false` over the whole body of a *successful*
  completion. A prologue is chosen before the outcome is known, so it cannot be a declaration in one
  case and absent in the other. This implementation follows the two cases that agree — the prologue
  is the declaration, and the document after it carries none — which leaves `c-mpu-0038` unsatisfiable
  as written. Cases are the contract and are not edited from the implementation side, so this is a
  maintainer decision of the same kind as `c-mpu-0018` and `c-etag-0001`.

- **A deferred operation contributes no route row, so thirty-four of the model's operations are
  still answered by a neighbour instead of being refused.** `GetObjectAttributes` was the reported
  case, the three object `?tagging` operations the second instalment, `GetBucketTagging`
  (previously answered by `ListObjects` with a page of keys) the third, the `?cors`, `?lifecycle`
  and `?encryption` bands the next three, and the object-lock family the latest — five lines at
  once, because its bucket read was a `ListObjects` claim and its four object operations were
  `GetObject` and `PutObject` ones. The class is not closed.
  The overlay declares the protocol-known operation set as `include ∪ deferred` — 25 + 87 = the 112
  operations the pinned model defines — and codegen already refuses an operation that is in neither
  list. What it does *not* do is emit a selector for a deferred one, so the route table knows 25
  shapes and the first-match order gives the rest away. Measured against `generated/routes.rs` by
  replaying each deferred operation's own `@http` selector through the table: `ListObjects` claims
  28 (`?acl`, `?policy`, `?versioning`, `?encryption`, every bucket subresource read), `GetObject`
  claims 6 (`?acl`, `?legal-hold`, `?retention`, `?torrent`), `PutObject` claims 6 (`?acl`,
  `?retention`, `?legal-hold`, `RenameObject`), `DeleteObject` 1, `ListBuckets` 1; 47 are correctly
  refused because their method or target matches nothing. The register is
  `scripts/allowances/route-coverage-allowances.txt`, and `scripts/check_route_coverage.sh` fails in
  both directions, so the count cannot drift in either. The `PutObject` group is the sharp one:
  `PUT /b/k?acl` with an ACL document as its body is currently a *write of that document over the
  object* — which is exactly what `PUT /b/k?tagging` was until the row at 490 landed. The fix is
  structural rather than per-operation — the `@http` trait already carries the method, the target
  and the query literals for all 112, as `GetObjectAttributes`' and the tagging band's rows show
  (their `QueryPresent(...)` predicates were derived, not hand-written), so codegen could emit
  a row for a deferred operation from the model alone, with precedence as the only overlay
  decision. Two things stop that landing here: `ShadowingPolicy::EveryOverlap` would ask for
  several hundred declarations for the bucket subresources (the trade-off already recorded above —
  the tagging band alone needed nine), and it is a route-table change of a size that wants its own
  review. Recorded rather than attempted.
- **`c-etag-0001` and four passing list cases assert contradictory `ListBucketResult` element
  orders, and nothing checks a case's assertion against the IR.** `c-etag-0001` exchange #2 asserts
  `IsTruncated, Contents, Name, Prefix, MaxKeys, KeyCount` — the `ListObjectsV2Output` member
  declaration order. `c-list-0001` (both pages), `c-list-0002`, `c-list-0012` and `c-list-0018`
  assert the order that starts with `<Name>`, as do all four checked-in reference bodies under
  `conformance/goldens/`, and as `q-order-0014` records with its own evidence. The two cannot both
  hold for one operation. The encoder is not the disagreement: it writes `ir.xml.element_order`
  faithfully, `lower/support.rs` already refuses an `element_order` that is not exactly the body
  member set, and the order it is given comes from `model/overlays/ops/list.toml`, deliberately and
  with a quirk attached. So this is a case-versus-case contradiction for a maintainer to adjudicate,
  not an implementation defect — and it survived because no gate compares a case's
  `expect.body.xml.element_order` with the operation's IR. Such a check is cheap and would have
  caught it at authoring time; it cannot land green until the contradiction is resolved, which is
  why it is recorded here instead.

- **The conditional cluster's declarations are wired; its *evaluation* cannot be, and the fixture's
  private mirror is what the suite is actually measuring.** `ops/get_object.rs`,
  `ops/head_object.rs` and `ops/put_object.rs` now `use` `shared::precondition` and `shared::etag`
  and declare a `CONDITION_KIND` and a `CONDITIONS` list each — the same declarative shape the four
  listing operations use for `shared::pagination`'s `CursorSpec`, and, like those, read by nothing
  yet. Three of the seven names in the two `//! Members:` lines are therefore now checkable against
  the `use` graph; `CopyObject`, `UploadPartCopy`, `CompleteMultipartUpload` and `DeleteObject`
  stay declaration-only, so the both-directions guard AGENTS.md asks for can be written for the
  object family but cannot yet be made total. What no `ops/<name>.rs` file can hold is the call to
  `evaluate`: each is a static `OperationSpec` and a floor, settled before a request is read, while
  evaluating a condition needs the object the *handler* resolved. So the caller is the backend, and
  `crates/gateway/src/lib.rs` re-exports `ops::shared::copy_source` and nothing else from this
  directory. `crates/conformance/src/fixture.rs` therefore answers `If-Match` out of
  `evaluate_conditions`, a hand-written mirror that disagrees with this crate on six outcomes:
  `If-Match` + `If-None-Match` together (400 here, 304 there), `If-Match: *` on a missing key (412
  / 404), a matching `If-Match` suppressing a failing `If-Modified-Since` (200 / 304), a missed
  `If-None-Match` with a satisfied `If-Unmodified-Since` (304 / 200), an `If-Modified-Since` in the
  server's future (200 / 304), and the strong comparison `If-Match` requires (412 / 200 on a weak
  validator). `If-Range` and `partNumber` are absent from the mirror altogether. Closing this is
  one facade export plus one backend edit — the same two-line shape the copy-source export took —
  and it is the whole of `c-cond-0013` … `c-cond-0021`, `c-range-0015`, `c-range-0018`.
  **Update — the inputs are no longer the obstacle.** `if-range` is now a declared binding on
  `GetObject` (synthesized in `model/overlays/ops/object.toml`, because no version of the pinned
  model carries the header) and `IfRange::parse` reads it, so `RangeSelectors::if_range` can be
  populated from a request for the first time. `Range` decodes to a `RangeSpec` that keeps its own
  source text, so `RangeSelectors::range` and the first argument of
  `HandlerError::unsatisfiable_range` are reachable too.
  `crates/gateway/tests/backend_reachability.rs` makes both calls using only the facade. What
  remains for `c-range-0010` and `c-range-0018` is the fixture edit and nothing else; `partNumber`
  is unchanged.
- **`OperationSpec` can require a parameter and cannot forbid a combination, so `c-cond-0014` and
  `c-range-0015` have nowhere declarative to live.** `RequiredParam` is `{kind, name,
  missing_error, message}` and `check_required` tests exactly one thing — `present` — so it
  expresses "this operation cannot proceed without X" and has no form for "X and Y must not both
  be sent". The two mutual exclusions the conditional cluster needs are `If-Match` with
  `If-None-Match` (400 `InvalidRequest`) and `Range` with `partNumber` (400 `InvalidRequest`);
  `evaluate` and `evaluate_range` already return them as a `PreconditionRejection`, but that is a
  value a *handler* produces, and both are properties of the request head alone — decidable before
  authentication, and `400` is already in the pre-auth status set. A `RequiredParam` sibling —
  `MutuallyExclusive { kind, names, error, message }`, checked in the same loop — would put them
  where the rest of the request-shape rules are. Recorded rather than worked around: the
  alternative is an `if` in every backend's handler, which is the per-implementation duplication
  `ops/shared/` exists to prevent. The change is in `crates/core/src/registry/mod.rs`.
- **`RangeDecision::Part` is a selector that `status()` already calls a `206`.**
  `evaluate_range` is given the object's total length and nothing about its part boundaries, so
  `Part` carries only the requested `partNumber`: `content_range()` answers `None` and
  `content_length()` answers the *whole* object's length. A `206` with no `Content-Range` is not a
  response RFC 9110 §15.3.7 allows, and `c-range-0007` asserts `x-amz-mp-parts-count` besides.
  Completing it changes the variant's shape — the part table has to reach `evaluate_range`, or the
  operation has to resolve `Part` itself — which is a contract decision, so it is recorded rather
  than guessed at.
- **`HandlerError` now carries headers and document elements; nothing in this workspace calls it
  yet.** `with_header`, `with_detail` and the two whole-refusal constructors
  (`unsatisfiable_range`, `precondition_failed`) close the framework half of what `c-cond-0001`,
  `c-cond-0023`, `c-object-0007`, `c-object-0014`, `c-range-0009`, `c-range-0010` and `c-range-0014`
  need. `PreconditionRejection` and `RangeDecision::Unsatisfiable` already hold the values —
  `Unsatisfiable` carries `actual_object_size` and `range_requested` for exactly this reason — so
  what remains is one edit in `crates/conformance/src/fixture.rs` to build the refusal from them
  instead of from a bare code and message. Until that lands the new capability is unexercised by the
  suite, and the numbers do not move. `range_requested` was additionally *unobtainable* until the
  `Range` binding started carrying its own source text; it now holds the header verbatim, and
  `crates/gateway/tests/backend_reachability.rs` builds the refusal from a decoded request to prove
  it. The fixture edit is the only step left.
- **The set of headers a backend may set is deliberately two variants wide.** `ErrorHeader` admits
  `Content-Range` (RFC 9110 §14.4, required on a 416) and `Retry-After` (§10.2.3). Anything a
  handler cannot express through those it cannot express at all — by design; see the admission rule
  in `src/fault.rs`. `x-amz-delete-marker` on a 404 over a delete marker is the next real candidate
  and is deliberately not pre-added.
- **`ELEMENT_ORDER` is a guess wherever no case pins it.** `Condition`, `RangeRequested` and
  `ActualObjectSize` are pinned byte for byte by `c-cond-0001`, `c-cond-0023` and `c-range-0010`.
  The relative order of `Key` and `BucketName` follows AWS's `NoSuchKey` document and is asserted by
  nothing; a case that pins it would turn the guess into a fact.
- **The copy family's second authorization stage lives in a type, not in `AuthRequirement`.**
  `AuthRequirement` carries one action and one resource shape, so `CopyObject` and `UploadPartCopy`
  declare only the destination's `s3:PutObject`. The source's `s3:GetObject` is enforced by
  `ops/shared/copy_source.rs`: `CopySource` has no accessor for its bucket or key, and the only way
  to a readable `ResolvedCopySource` is `resolve(&SourceAuthorized)`, whose argument only
  `authorize_source` can produce. That makes the omission behind GHSA-mx42 / GHSA-wfxj a compile
  error rather than a review miss, and it is deliberately *not* a second `AuthRequirement` field —
  when P4-05 lands `DerivedResources`, the two should be joined and this note deleted.
- **The copy result structures are flattened by the overlay, because the encoder has no structure
  payload.** `CopyObjectOutput.CopyObjectResult` and `UploadPartCopyOutput.CopyPartResult` are
  `httpPayload` structures, and `emit/codec/encode.rs` accepts only a blob in payload position. The
  overlay therefore drops each structure and synthesizes its two wire members as ordinary body
  members under a root named for the structure, which produces identical bytes and a flatter dto.
  A structure form in the payload encoder would let the model shape be kept; that file belongs to
  the codec task, so this is recorded rather than fixed here. `GetObjectAttributes` will hit the
  same wall.
- **`PROVISIONAL_SHADOWING` gained five copy rows, and the last one is not a refinement.**
  `UploadPart` over `CopyObject` is the only pair in the table where neither selector contains the
  other, so it is resolved by band order rather than by specificity. `UploadPartCopy` at 400 claims
  every request that could reach it, so the row records a decision nothing currently exercises —
  which is exactly the kind of row `ShadowingPolicy::TotalOnly` would stop requiring.
- **P4-05 will add `Operation::DerivedResources`, and that breaks every `impl Operation`.**
  Associated types cannot have defaults, so adding one is a breaking change for every operation
  module. If P5 is to run in parallel, P4-05 should land its associated type first, or accept a
  mechanical edit across every operation file.
- **`register_handler` now requires `O: OperationCodec`, and that is a public API tightening.**
  `OperationCodec` stays a separate trait from `Operation` — a third party may still *name* an
  operation without writing a codec — but registering a handler for one now takes the explicitly
  named `register_handler_without_codec`. Every in-tree call site is an AWS operation and all
  sixteen have generated codecs, so nothing moved except `tests/registration.rs`, whose third-party
  fixtures deliberately have no codec. The alternative — leaving `register_handler` at
  `O: Operation` and adding a codec-carrying sibling — was rejected because
  `#[rustfs_gateway_macros::handlers]` emits `RouterBuilder::handle`, so the *default* path is the
  one that must carry the codec or every macro-registered backend would assemble unserveable.
- **The erased payload is still `Box<dyn Any + Send>`, and now both ends of it are pinned down.**
  It holds a `Req<O>` on the way in and a `Resp<O>` on the way back, and what produces and consumes
  those boxes is the codec erased from the same registration. A wrong box is answered
  (`500 InternalError`), never panicked, on both the handler side and the encoder side.
- **`ErasedEncode` takes no status parameter, unlike `OperationCodec::encode`.** The erased form is
  handed a `Resp<O>`, which already carries the status the handler chose — the declared success
  status, or a `206`/`200` it overrode. A second status argument would let the caller contradict the
  handler with nothing to say which is right. A facade written against a three-argument encoder
  needs the drop of that argument, and `tests/codec_binding.rs` pins the behaviour.
- **`OperationCodec` decides the status from the handler's `Resp`, and applies the RFC 9110 body
  invariants last.** A `HEAD` response and a `1xx`/`204`/`205`/`304` lose their body in
  `EncodedResponse::enforce_http_invariants`, once, for every operation — never per operation. The
  *decision* behind it is `body_allowance(method, status)`, separate from the enforcement, because a
  refusal never reaches an encoder and the facade has to reach the same conclusion over an
  `http::Response`. One rule, two enforcement sites, and neither holds a copy of it.
- **`Resp<O>` is a status plus an `Answer<O>`, and the second variant is the commit seam.**
  `Answer::Settled` is what every handler produced before; `Answer::Committed` holds a `CommitWork`
  whose output is `Result<O::Output, HandlerError>` — statusless, deliberately, because by the time
  it resolves the status line has been sent. There is no run-time check that a committed response
  keeps its status: after `Resp::commit` there is no value a status could be written into, and
  `Resp` has never had a setter. **This is a breaking change** (ADR-0004: `0.x` minor releases may
  break): `Resp::output` and `Resp::into_output` now answer `Option`, and `Resp::into_parts` yields
  an `Answer<O>` rather than an `O::Output`. Every handler-side spelling — `Resp::new`,
  `Resp::with_status`, `HandlerResult<O>` — is unchanged, which is what keeps existing backends
  compiling.
- **`OperationSet` is a name set, not a bit set, and there is no `AWS_CORE`.** An index-based set
  needs a generator to assign the indices, and a curated `AWS_CORE` would be a second source of
  truth about which operations exist. Both belong in codegen; `OperationSet::aws_full()` reads the
  route table.
- **`AuthRequirement` lives in `op.rs` and is deliberately minimal.** P4-05 owns the full
  authorisation shape; this is the least that lets registration refuse an operation nobody can
  authorise, and the two should be merged when P4-05 lands.
- **`tests/purity_guard.rs` gained a file-level allowance list.** `registry/handlers.rs` awaits,
  because calling a handler is what it does. The store-word detector now matches whole identifier
  segments instead of substrings, so `Handler` is no longer read as `Handle`; every catch the
  substring version had is still asserted, including `ObjectStore` and `ConnectionPool`.

- **`ShadowingPolicy` defaults to `EveryOverlap`, as the design asks, and it is quadratic.** Once
  thirty bucket subresources are in the table, every `?acl`/`?tagging` pair overlaps and the strict
  policy asks for several hundred declarations that all say the same thing. `TotalOnly` keeps the
  guarantee that matters — no route is silently unreachable — without the paperwork. Switching the
  default is a decision, not a cleanup; both are implemented and tested.
- **`PROVISIONAL_SHADOWING` belongs in `model/overlays/route.toml`.** That path is outside this
  task's file scope, so the one declaration the generated table needs lives here in the same four
  fields the overlay will use. P4-06 should move it and delete this static.
- **`tests/golden/route-table.txt` should join the protected-files list** — it is the artefact that
  makes a model upgrade's routing change visible.
- **`RoutePredicate` has eight variants, `Predicate` has ten.** `HostClass` and `ArnForm` are in the
  frozen IR schema and here, but `rustfs-gateway-model`'s `Predicate` does not carry them, so
  codegen cannot emit them and no generated row can use them yet.
- **`QueryEquals` compares the still-encoded value.** Every routing value in the model is an ASCII
  token, so it does not matter today; `list-type=%32` would not route. Decoding on the pre-auth path
  is the alternative.
- **`MissingContentLength` (411) cannot be a `RequiredParam` code**, because the pre-auth set is
  `{400, 403, 501}`. That looks right — a missing `Content-Length` is a framing fact acceptance
  already refuses — but it is a real constraint on how P5 writes specs.
- **P4-03's canonical-header half is already upstream.** `rustfs-gateway-sig` /
  `rustfs-gateway-http` verify `SignedHeaders` is ascending and look up by name without sorting.
  Nothing was needed here, and nothing here duplicates it.

## Verify

```bash
cargo test -p rustfs-gateway-core                                  # 250 tests
cargo clippy -p rustfs-gateway-core --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/check_license_headers.sh
bash scripts/check_layer_dependencies.sh
bash scripts/check_ring_boundaries.sh
bash scripts/check_no_planning_docs.sh
UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-core --test golden    # only when the change is intended
```
