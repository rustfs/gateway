# ADR-0036: A trailing catch-all template parameter

- Status: Accepted
- Date: 2026-09-30
- Trigger: axiom A4, because what a claimed row matches and hands its handler is decided per template segment. Also a crate boundary: `rustfs-gateway-core`'s `PathTemplate` accepts a template it refused before, and `TemplateRejection` gains a variant.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 (b) and ADR-0030 (c) and leaves their text unchanged.

ADR-0024 (b) made every template parameter one whole segment, so a template never matches across
segments. RustFS main now registers its heal route with a catch-all: `POST
/rustfs/admin/v3/heal/{bucket}/{*prefix}` (`rustfs/src/admin/route_policy.rs:355`,
`rustfs/src/admin/handlers/heal.rs:214` at `3268c42e00b375859b4535d53fe219b02d7bfe31`), where the
inventory recorded `{prefix}` at `736e4fb8` (rustfs/gateway#1172). The change came with
rustfs/rustfs#7653 on RustFS's release branch and reached main with rustfs/rustfs#7935.

What RustFS does, read at `3268c42e`:

- **`matchit` 0.9.2's catch-all** must be a route's last segment and matches everything to the end
  of the path: separators, empty and dot segments and escapes, as the raw path carries them. It
  never matches an empty value. The static node before it holds no route, so
  `POST …/heal/photos/` reaches nothing (`src/tree.rs`, the `CatchAll` arm of `Node::at`; the
  crate documents `/{*rest}` refusing `/`).
- **The heal handler decodes the captured value once**, with
  `percent_encoding::percent_decode_str(…).decode_utf8()`: a `%` that two hexadecimal digits do not
  follow stays as it is, and a result that is not UTF-8 is refused (`heal.rs:76-89`). It validates
  the result as an object prefix afterwards — no `.` or `..` component, no `//`, no NUL, at most
  32 KiB (`heal.rs:163-175`; `crates/ecstore/src/bucket/utils.rs:109-163`) — and all of this runs
  after the handler has authorised the request (`heal.rs:1438-1464`).
- The gateway decodes an object key the same way (`rustfs_gateway_types::decode_once`): one pass,
  a malformed escape kept, strict UTF-8.

## Decision

**(a) A template may end in one catch-all, `{*name}`.** The name follows the parameter rule
(`[a-z_][a-z0-9_]*`) and appears once in the template. Nothing may follow a catch-all: a segment
after it, a second catch-all or a trailing `/` is refused as `TemplateRejection::CatchAllNotLast`.
Every other spelling (`{*}`, `{**x}`, `{*X}`, `x{*y}`) is `MalformedParameter`.

**(b) A catch-all matches the rest of the raw path after the separator before it, when that rest
is at least one byte.** Separators, empty segments, dot segments in any spelling and encoded
separators are all part of the value. Every segment before the catch-all keeps its own rule, so a
bound `{bucket}` is still one segment that meets the S3 name rules. Matching stays allocation-free
and synchronous.

**(c) The value is decoded once, exactly as RustFS's handler decodes it.** Every well-formed escape
is decoded once, a `%` without two hexadecimal digits is kept, and only a result that is not UTF-8
is refused: a `400 InvalidArgument` naming the parameter, before authentication, that never echoes
the value, as for every parameter. Nothing else is refused. Validating what the rest names is the
handler's, as it is RustFS's today. The handler reads the value from
`RequestContextView::path_params()` and must not decode it a second time.

**(d) Overlap and refinement follow from (b).** A catch-all overlaps a longer fixed template whose
extra segments spell at least one byte, and any other catch-all whose fixed prefix meets its own.
A fixed template refines a catch-all when it is longer than the catch-all's prefix, its prefix
refines that prefix, and its extra segments are not a lone trailing `/`. A catch-all refines only
another catch-all whose prefix is no longer than its own and which its prefix refines. Overlaps
between claimed rows still owe declarations exactly as ADR-0024 (b) requires. RustFS's three heal
routes — `heal/`, `heal/{bucket}` and `heal/{bucket}/{*prefix}` — share no path and declare
nothing.

**(e) A catch-all is never a bound bucket.** A bucket is one segment, so `ClaimedRoute::bucket_param`
naming a catch-all is refused as `DialectError::ClaimedBucketParam`.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- RustFS was read at `3268c42e00b375859b4535d53fe219b02d7bfe31`. The file and line references are
  in Context. `matchit` 0.9.2 was read from the published crate.
- Core, measured by `cargo test -p rustfs-gateway-core --lib -- route::claim n_a_catch_all_is_never`:
  `route/tests/claim.rs` holds the rules (a rest of one byte or more, across segments; never an
  empty rest or a short path; the once-decoded value and the one refusal; misplaced and misspelled
  catch-alls; overlap and refinement in both directions, each overlap path matched by both
  templates; the three heal routes sharing no path), and `registry/reject_rule_tests.rs` refuses a
  catch-all as a bound bucket.
- Core, measured by `cargo test -p rustfs-gateway-core --test integration -- dialect_claims`: a
  catch-all row reaches its operation across segments and extracts the decoded rest; an empty rest,
  a short path and another method are the claim's `501`; a literal row, or a narrower catch-all,
  inside a catch-all's reach conflicts at one precedence and owes a declaration across
  precedences; declared in front, the literal answers only its own path.
- The facade, measured by `cargo test -p rustfs-gateway --test integration -- dialect_claims_runtime`:
  the decoded rest reaches the handler context, the operation stays service-level at both
  authorizer stages, a value that is not UTF-8 is a `400` before the authorizer is asked, and a
  rest with nothing in it is the claim's `501`.
- Every assertion added here has a mutation that turns it red. The PR lists each one.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Keep whole-segment parameters and declare heal with `{prefix}` | RustFS main serves `heal/photos/a/b`; the gateway would answer it with the claim's `501`. |
| Refuse dot segments, `//` and control characters in the value before authentication, as a parameter's | RustFS matches them and refuses them in its handler after authorisation, with its own answer; the gateway would answer a request RustFS answers differently, and the handler validates the value anyway. |
| Decode strictly, refusing a malformed escape | RustFS keeps a `%` without two hexadecimal digits, and so does the gateway for an object key; `100%zz` is a legal key. |
| Hand the value raw and let the handler decode it | Two decoders for one value is how a value gets decoded twice or not at all; every other parameter is decoded once, by the facade. |
| Allow a catch-all anywhere in a template | `matchit` refuses it, and a catch-all in the middle makes one path match in more than one way. |
| Let a catch-all be the bound bucket | A bucket is one segment; the S3 name rules could not apply to several. |

## Consequences

- **BREAKING**: `rustfs-gateway-core` 0.49.0. `TemplateRejection` gains `CatchAllNotLast`, so an
  exhaustive match adds it. `PathTemplate::catch_all` is new. A template ending in `{*name}` was
  refused as `MalformedParameter` and now parses; every template that parsed before matches,
  extracts, overlaps and refines exactly as before.
- **Handler contract**: a catch-all value arrives decoded. A RustFS handler registered against a
  catch-all row — the heal handler — reads it from `RequestContextView::path_params()`, does not
  percent-decode it again, and keeps its own validation.
- **Enforcement**: the tests listed under Evidence; `crates/core/tests/purity_guard.rs` (matching
  stays synchronous and store-free); the claimed table's overlap and declaration checks; the
  registration refusal of a catch-all bucket.
