# ADR-0040: Opaque single-segment captures

- Status: Accepted
- Date: 2026-10-06
- Trigger: axiom A4, because an extension route must distinguish matching a raw segment from interpreting the data it contains.
- Supersedes / Superseded by: none

## Context

ADR-0024's `{name}` parameter is strict: dot segments and encoded separators cannot match it,
and extraction rejects malformed escapes, controls and invalid UTF-8. ADR-0036's `{*name}`
instead captures the nonempty remainder and decodes it as opaque UTF-8 data. Neither expresses
one raw segment whose contents belong to a vendor handler.

[Gateway #1311](https://github.com/rustfs/gateway/issues/1311) records the consequence for
ADR-0039. Native RustFS matches a registered admin route before trying its v4 downgrade. A
nonempty raw `id` such as `%2e%2e` or `a%2Fb` still belongs to the registered plugin-instance
route. The gateway's strict parameter rejects it during matching. Adding a broad fallback
would then answer 426 and tell the client to downgrade an already registered operation.

Changing every `{name}` to admit such values would silently remove an existing restriction.
Using a catch-all would also accept empty intermediate segments and additional path segments.
The distinction must be explicit in the template a reviewer reads.

## Decision

Add `{+name}` for one nonempty raw segment, at any parameter position. Its name has the same
lowercase grammar and uniqueness rules as the other captures. No affix or combined modifier is
allowed. Literal `/` separates segments; encoded `/` is data within one raw segment.

Match first, then decode exactly once with the existing opaque name decoder. Valid percent
escapes become bytes, an incomplete or malformed escape remains literal, and invalid UTF-8 is
refused without echoing the value. Dot segments, decoded separators and control characters are
passed as data. A handler must validate what that data means; this spelling is not a guarantee
that the value is safe as a filesystem path. `raw_value` still returns the original bytes.

Keep the other two spellings unchanged:

| Capture | Raw extent | Decoded value |
| --- | --- | --- |
| `{name}` | One nonempty segment, excluding dot segments and encoded separators | Strict segment |
| `{+name}` | Exactly one nonempty segment | Opaque UTF-8 |
| `{*name}` | One or more remaining bytes; only at the end | Opaque UTF-8 |

The overlap and refinement lattice uses what the matcher accepts, not whether later extraction
or a handler succeeds. A strict parameter refines the otherwise identical opaque parameter;
the reverse is false. Both overlap, neither overlaps an empty trailing literal, and an opaque
capture cannot consume a following segment. A trailing catch-all contains either one-segment
capture at the same position, but neither contains the catch-all. Existing sourced shadowing
declarations and conflict checks continue to apply.

Claim containment still requires literal claim-prefix segments. An opaque parameter cannot
stand in for a tenant or API segment in the owning claim. Existing bucket bindings continue to
validate the raw bucket label, and subject rules, authentication floors, authorization stages
and handler registration remain unchanged.

No existing operation opts in through this ADR. The admin generator's follow-up must change its
templates explicitly, preserve its inventory records, and prove that registered operations
still win over the proposed fallbacks. In particular, a malformed parameter value must not be
reclassified as a missing operation just to make the fallback tests pass.

## Evidence

- Measured against frozen RustFS `5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744`: 36 HTTP requests
  in #1311 cover both aliases, six plugin-instance path forms and three credential states.
  With valid credentials, ordinary absent ids, encoded dot segments, encoded separators and
  encoded NUL produce 400 InvalidArgument. An empty id or an additional trailing slash produces
  empty 426. Forged and anonymous companions produce 403. This records native responses, not
  gateway backend acceptance.
- [Frozen native router](https://github.com/rustfs/rustfs/blob/5e1bd498ce1ca33bcb0ca50aeee861e69e6c8744/rustfs/src/admin/router.rs#L3359):
  it invokes the raw method/path match before considering the downgrade branch.
- Measured in the draft #1189 assembled service: the ordinary id reaches its recording handler,
  while `%2e%2e` incorrectly receives 426. The new regression fails at that status comparison.
  The test expects the recording handler's own answer and decoded parameter, not the native
  handler's particular error, so routing is measured separately from backend validation.
- Measured with `cargo test -p rustfs-gateway-core --lib route::claim::tests`: all 22 cases pass.
  Seven of the eight new cases first failed at the old parser's `MalformedParameter` refusal;
  the new invalid-grammar case already passed. The cases cover decoding, names and order,
  exact raw extent, UTF-8 refusal, the strict control, malformed grammar, claim containment,
  and every direction in a six-template overlap/refinement matrix with real path witnesses.
- Measured: all 28 deliberate faults are caught by a new opaque-capture test, covering parsing,
  empty and excess segments, decoding and UTF-8 refusal, binding names/order, strict controls,
  claim containment, and overlap/refinement witnesses. The implementation is restored after
  each fault; compilation failures do not count as kills.
- [Inferred] This explicit capture is sufficient to express the native matcher's parameter
  coverage without widening existing templates. Only an admin-generator opt-in and assembled
  routing controls can prove that it fixes the fallback integration.

## Rejected alternatives

| Alternative | Reason rejected |
| --- | --- |
| Widen `{name}` globally | Existing routes would lose a restriction without any declaration changing. |
| Use `{*name}` | It also consumes literal separators and additional path segments, and cannot be a middle capture. |
| Return a fallback after a parameter fails validation | A known route becomes a downgrade signal rather than keeping its operation. |
| Decode the entire path before matching | An encoded separator would become a segment boundary; native raw-prefix controls distinguish those cases. |
| Add a callback that decides whether a failed route was close enough | That puts another matcher outside the template and its overlap checks. |

## Consequences

This is a public template-grammar extension, with no new public Rust type. Existing strict and
catch-all templates retain their meaning. The private decoder helpers move to a sibling module
to keep the matcher under the 800-line limit; their algorithms are unchanged.

The feature does not install admin fallbacks, change the native inventory or waive later value
validation. #1189 remains incomplete until its generator, handler registration, wire controls
and the registered-route regression are satisfied. Public-contract review is required before
this new spelling lands.
