# ADR-0007: Runtime vtables for dialect XML fields

- Status: Superseded by ADR-0010
- Date: 2026-08-10
- Trigger: dialect codec strategy
- Supersedes / Superseded by: ADR-0010

## Context

Some S3-compatible implementations persist XML elements that are absent from the AWS model. A
representative example is MinIO's `DelMarkerExpiration` child of `LifecycleRule`. Putting such a
member in the standard DTO would make dialect state part of the AWS-facing type and output. Making
an entire second generated codec for each dialect avoids that contamination but repeats almost all
generated code.

The frozen IR already reserves an `ext_points` record whose strategy is either `ExtField` or
`GeneratedVariant`. The unresolved question was whether one static parent codec could round-trip a
typed extension without naming the extension's concrete Rust type. The time-boxed
`ext-field-spike` crate tests exactly one parent and one extension. It is evidence, not production
code.

The spike uses quick-xml 0.41's pull reader and event writer. Its parser configuration has no byte,
depth, element-count, or DTD policy, so the spike enforces those limits outside quick-xml. It does
not install an entity resolver and rejects every DOCTYPE event before reading the document body.
[quick-xml reader](https://docs.rs/quick-xml/0.41.0/quick_xml/reader/struct.Reader.html),
[quick-xml configuration](https://docs.rs/quick-xml/0.41.0/quick_xml/reader/struct.Config.html),
[quick-xml entity resolver](https://docs.rs/quick-xml/0.41.0/quick_xml/de/trait.EntityResolver.html).

## Decision

Use one generated codec plus runtime `ExtField` vtables for registered dialect elements. Pass a
borrowed `CodecPolicy` into decode and encode; never use a process-global registry and do not store
the policy in `Req<O>`. Store decoded extension values in a TypeId-indexed `Extensions` map. Emit
each registered extension at an explicit known-sibling insertion slot. The parent codec rejects an
insertion slot it does not implement.

This decision proves only element-shaped XML extensions. Header extensions, JSON extensions,
literal-body dialects, multiple parents, and nested extension points require separate evidence.
The spike does not authorize moving its implementation into production crates; that is a separate
task using this ADR as input.

For ordinary request XML, the default unknown policy is `lenient`: registered fields decode and
unregistered subtrees are skipped with limits. For security-relevant request configuration, the
default is `allow-registered`: registered fields decode and every other unknown field is rejected.
`deny` is an explicit stricter mode and rejects registered fields too.

Persisted bucket configuration is a separate safety boundary. `lenient` is not a lossless
read-modify-write policy: case `c-ext-n016` proves that an unregistered persisted element is
removed on re-encode. Production persistence code must therefore retain the original bytes until
all persisted extension points are registered, and any parse or registration miss must abort the
transaction without replacing the stored document. It must never translate a parse failure into
an absent configuration. This makes a missing registration visible without silently disabling
versioning, WORM, encryption, or another stored control. `deny` remains forbidden as the default
for persisted data; it has no forward-compatibility path.

## Evidence

### Q1: Can a static codec encode a type it does not know?

**Conclusion: yes.** `LifecycleRule::encode_xml` enumerates `ExtVTable` entries and invokes an
erased function pointer using a TypeId-indexed value. `c-ext-0001`, `c-ext-0002`, and
`c-ext-0003` prove typed decode, vtable encode, and byte-identical round-trip. `c-ext-0004` and the
required source grep prove that `spikes/ext-field/src/lifecycle_rule.rs` does not contain the
concrete dialect type name.

### Q2: Can decode dispatch registered unknown elements safely?

**Conclusion: yes, within the declared three-state policy.** `c-ext-n001` and `c-ext-n002` prove
that lenient mode skips both a leaf and a complete nested subtree without cursor drift.
`c-ext-n003` proves that allow-registered rejects an unregistered element. `c-ext-n004` proves
that deny rejects even a registered element. Duplicate `(parent, local-name)` registrations fail
without panic in `c-ext-n011`.

Skipping remains bounded. `c-ext-n005` through `c-ext-n010` prove the depth, DOCTYPE, entity,
external-entity, element-count, and byte limits. `LifecycleRule::decode_reader` reads at most
`max_bytes + 1`; the extra byte distinguishes an exactly-full valid body from an oversized body
without buffering the remainder. The counting-reader assertion in
`c-ext-n010` measures that boundary. `c-ext-n008` points its external entity at a real, existing
secret file. Its separate AST guard recursively scans `src/**/*.rs`, rejects filesystem and
process capabilities including aliases, and rejects direct or `cfg_attr`-wrapped `#[path]` plus
`include!` source escapes. Because token-splitting local macros are opaque to that AST walk, the
spike permits no local `macro_rules!` definitions. A TOML manifest guard resolves package aliases,
target tables, and workspace inheritance while holding runtime dependencies to quick-xml alone.
The secret fixture by itself is not treated as proof that no file read occurred.

### Q3: What does a runtime policy cost?

**Conclusion: the lookup is small, the no-extension request path adds no heap allocation, and
`Req<O>` need not grow.** The policy is borrowed by the codec call and is not stored in the
request. On the measured 64-bit target the borrowed reference is 8 bytes in the call ABI. The
candidate is measured against a numeric snapshot of the real
`rustfs_gateway_core::Req<PutBucketLifecycleConfiguration>` on the named `origin/main` baseline;
the spike never substitutes its own request carrier for that framework type. The snapshot baseline
is `origin/main@f4d90745b0ebe20349338638442d230426c7ca2c`.

The release-mode measurement below used `rustc 1.97.1 (8bab26f4f 2026-07-14)`,
`aarch64-apple-darwin`, Apple M4:

```text
$ cargo test -p ext-field-spike --release --test roundtrip c_ext_0005_no_extension_is_identical_to_baseline -- --nocapture
Q3 lookup: 2000000 iterations in 17.844125ms, 8.92 ns/lookup; policy ref: 8 bytes; main Req snapshot: 136 bytes; candidate Req: 136 bytes
```

The registered-policy lookup itself performs no allocation. An empty per-request `Extensions`
map also allocates nothing. Decoding the one registered field creates one boxed typed value and,
on the first insertion, one hash-table allocation: two additional heap-owning allocations for a
rule that carries this extension. The spike field's integer-to-text encoding creates one temporary
string; policy lookup does not. These are source-counted allocations, not allocator-call traces,
because repository policy forbids unsafe allocator instrumentation in the spike.
`c-ext-0005` measures the real framework request and compares it with the baseline snapshot.
Changing the snapshot or temporarily adding a field to the real `Req` made the case fail during
mutation testing.

### Q4: Where is an extension written?

**Conclusion: at its declared known-sibling insertion slot.** MinIO's canonical lifecycle rule
places `DelMarkerExpiration` after `Expiration` and before `ID`, `Filter`, and `Status`, so this
field declares `INSERT_AFTER = "Expiration"`. The static parent codec invokes registered vtables
at that point and fails closed for an unsupported slot. `c-ext-0003` uses that real dialect order
and proves byte-identical round-trip. `c-ext-n014` proves that a premature extension remains
readable but is moved into its declared slot on encode, and that an unsupported insertion slot
fails closed. With no registration, standard output is unchanged. A strict AWS-only schema can
still reject the extra element wherever it appears; this mechanism targets explicitly selected
dialect endpoints and does not add the element to standard AWS output. The ordering fact comes
from the pinned
[MinIO lifecycle rule definition](https://github.com/minio/minio-go/blob/b15d168a44068ef7f970fc695ca731b3c7754cd1/pkg/lifecycle/lifecycle.go#L545-L556).

### Q5: Is this an uncontracted `Any` downcast?

**Conclusion: no.** `Any` requires a static concrete type and exposes its `TypeId`.
[Rust `Any`](https://doc.rust-lang.org/std/any/trait.Any.html). Registration records that TypeId in
the vtable, decode inserts under the same key, and encode downcasts only after retrieving that key.
A lookup for a different type has the documented result `None`, proven by `c-ext-n012`; a vtable
and stored-value mismatch is an explicit error. This differs from an uncontracted payload
`as_any()` probe, where neither the key nor a miss has protocol meaning. No unchecked downcast and
no unsafe code is used.

### Q6: Is there a simpler mechanism with the same outcome?

**Conclusion: no alternative is simpler across both the standard DTO boundary and more than one
dialect.** Three smaller local mechanisms were considered:

| Alternative | Local advantage | Why it is worse for the stated outcome |
| --- | --- | --- |
| Generate a second codec per dialect | No runtime lookup or downcast | Repeats the static codec and makes every dialect change a large generated diff; the duplication grows by affected operation family |
| Add the member to the standard DTO | Simplest single-codec implementation | Pollutes the AWS type and can emit a non-AWS element to standard clients; different dialects can claim incompatible meanings |
| Use a closed enum of all extension fields | Avoids `Any` | Moves every dialect type into the protocol kernel and requires editing the central enum and parent codec whenever a dialect adds a field |

The vtable is worth retaining because it is the smallest mechanism that keeps the static parent
codec independent, the standard DTO uncontaminated, and registration runtime-owned rather than
global. If production evidence shows that registrations are fixed at compile time or that
lookup/allocation cost matters on a measured hot path, generated variants can still be selected
per IR extension point.

### Case matrix and sources

The spike contains exactly the five positive and sixteen negative cases specified by backlog
task P1-08. `cargo test -p ext-field-spike` reports 21 passed. The source grep reports zero matches.

| Evidence group | Cases | Contract |
| --- | --- | --- |
| Typed vtable round-trip | `c-ext-0001`–`c-ext-0003` | Registered type decodes, encodes, and round-trips byte-for-byte |
| Static-codec independence and baseline | `c-ext-0004`–`c-ext-0005` | Parent source does not name the dialect type; unregistered standard XML is unchanged |
| Unknown-element modes | `c-ext-n001`–`c-ext-n004`, `c-ext-n013`, `c-ext-n016` | Lenient, allow-registered, deny, and persisted-loss boundaries are observable |
| XML resource safety | `c-ext-n005`–`c-ext-n010` | Depth, DTD, entity, external-entity, element-count, and byte limits fail closed |
| Registry, ordering, and atomic encode | `c-ext-n011`, `c-ext-n012`, `c-ext-n014`, `c-ext-n015` | Duplicate keys fail, misses return None, slots are canonical and bounded, and encode errors expose no partial XML |

The protocol shape is based on the official lifecycle request and rule descriptions; the dialect
field is deliberately absent from the AWS member list.
[PutBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html),
[LifecycleRule](https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRule.html). The unknown
subtree behavior follows the compatibility fact recorded by
[s3s PR 617](https://github.com/s3s-project/s3s/pull/617); only that fact and link are used here.

## Rejected alternatives

Generating an entire MinIO codec variant is rejected as the default because the single vtable
meets Q1 and preserves one static parent codec. It remains the per-extension fallback represented
by `GeneratedVariant` in the frozen IR.

A process-global extension registry is rejected. Different gateway instances in one process must
be able to select different dialects, and a global registry would also make tests order-dependent.

Emitting every extension after all known fields is rejected. It rewrites the pinned MinIO
canonical order and therefore cannot provide byte-identical round-trip for the selected dialect.

Opaque preservation of the whole rule as an XML tree is rejected. It would preserve bytes but
would stop the parent from being a typed codec. Opaque preservation of only unregistered persisted
subtrees is not decided here; `c-ext-n016` records why persistence work must resolve that boundary
before replacing stored bytes.

## Consequences

- Production codegen can keep one static codec and emit a policy hook at declared IR extension
  points. It must not import concrete dialect types.
- Runtime assembly owns `CodecPolicy`; no global registry is introduced.
- Extensions are emitted at their declared known-sibling slot. Byte-identical round-trip is
  guaranteed only for an input already in the selected dialect's canonical order.
- Persisted read-modify-write remains blocked until every required stored extension is registered
  or a separately reviewed lossless preservation mechanism exists. A lenient parse alone is not
  persistence evidence.
- The production implementation must carry the same duplicate-registration, atomic-encode, DTD,
  depth, element-count, and byte-limit tests. The spike crate is excluded from default workspace
  members and is never published.
- The deterministic tests and the source grep are the enforcement mechanism for this ADR's spike
  conclusion. A production task must add equivalent generated-code guards before enabling an IR
  extension point.

VERDICT: ExtField: FEASIBLE
