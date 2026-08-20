# Protocol hazards

## Copy source authorization is a consuming transition

`CopyObject` and `UploadPartCopy` authorize two different resources: write access to the
destination and read access to the source named by `x-amz-copy-source`. The source is parsed and
normalized once into `CopySourceResources`, then exposed to policy as `s3:GetObject` or
`s3:GetObjectVersion`. The input-stage policy request retains the destination route and the full
source identity: path versus ARN, ARN partition/region/account, access point or outpost, and exact
version ID. That lets a destination policy constrain allowed copy sources without collapsing two
ARNs into one bucket/key pair. Dispatch can receive only `Authorized<O>`, and the handler can reveal
the normalized source only with the exact resource-bound `AuthorizedRead` proof carried by its
request. The route and input stages also receive one `RequestContext`, containing one clock reading
and one opaque policy snapshot.

This prevents three independent failures: a new operation cannot omit `DerivedResources`, the
framework visits every resource in a batch, and the backend does not parse a second source value
after policy has approved the first. `DeleteObjects` follows the same rule: its raw mutable object
list is cleared after derivation, and the backend executes only the proof-gated key/version view.
Runtime coverage is the 16-case `authz/` family, including
source denials, traversal refusals, policy failure, `Indeterminate`, and a policy update between
the two stages; compile-time coverage is under `crates/core/tests/compile_fail/authz_*.rs`.

## A character XML 1.0 cannot represent is refused on the way in and unwritable on the way out

XML 1.0 admits tab, newline and carriage return out of the C0 controls and excludes the rest
**entirely** — `&#1;` is as illegal as the raw byte, because a character reference to a character
outside the `Char` production is itself a fatal error. `U+FFFE` and `U+FFFF` are excluded on the
same rule; `U+007F` is not, because it is XML 1.1 that requires DEL to be escaped and S3 speaks
1.0.

The hazard is that this is not a lost member, it is a lost document. A raw `U+0001` in one
`<Value>` makes the whole response fail to parse, so one such value hides every sibling value in
the same body from every conforming client. `quick-xml` does not validate the character range, so
without an explicit rule such a value is read, stored and echoed.

**The rule is one predicate, `rustfs_gateway_xml::is_xml_representable`, called from both ends:**

- **Ingress — refused.** `rustfs_gateway_xml::read` rejects element text, CDATA, a resolved
  character reference, an attribute value and a name carrying such a character, with
  `XmlError::ForbiddenCharacter`. Every generated decoder of an XML body already funnels through
  that parser, so this reaches every operation with no per-operation call an author can forget, and
  it surfaces as the `400 MalformedXML` the parse failure already mapped to.
- **Egress — unwritable.** `rustfs_gateway_xml::write` substitutes `U+FFFD` for such a character in
  all three escaping passes. This is a backstop, not the mechanism: no caller-supplied value gets
  past the ingress refusal, but a read answers from whatever the backend holds, and a value stored
  through another channel would otherwise break every read of that document. On the listing path it
  is never reached — a stored key that fails the predicate is percent-encoded first
  (`ObjectKey::needs_url_encoding`, `c-list-0035`).

Refusing at ingress and substituting at egress is deliberate, and neither end can stand in for the
other: ingress alone leaves the stored-value case unguarded, and egress alone would answer `200` to
a request whose value is silently not the one that was sent.

**What AWS does, and where the record stops.** The ingress half matches captured AWS behaviour:
a `DeleteObjects` body carrying a raw C0 control in a `<Key>`, and the character-reference spelling
of the same byte, were both answered `MalformedXML` / `400` by real S3, reproduced in-house by AWS
(https://github.com/aws/aws-sdk-java/issues/333, and independently
https://github.com/boto/boto3/issues/2005). The egress half is a **deliberate divergence**: AWS
serialises such a character into a `200` response as `&#x7;`, which is itself illegal XML 1.0, and
has declined to change it (https://github.com/boto/botocore/issues/3496); its own documentation
says a `200` response can contain invalid XML and offers `encoding-type` as an opt-out on the
operations that have one. Configuration reads have no such parameter, so matching AWS byte for byte
here would mean shipping the defect.

**Left open for want of a capture, in the manner of ADR-0008's `<Condition>`:** no capture exists
for `PutBucketTagging` or `PutBucketLifecycleConfiguration` specifically, and S3 tags carry an
extra character allowlist of their own, so it is possible AWS answers `InvalidTag` rather than
`MalformedXML` on the tagging channel. Parse-before-validate makes `MalformedXML` the likelier
answer and it is what this gateway does; a single captured `put-bucket-tagging` would settle it.

Pinned by `conformance/cases/lifecycle/c-lifecycle-0033`…`0037`,
`conformance/cases/object/c-object-0039`, `crates/core/tests/xml_character_range.rs` and the
character-range block of `crates/xml/src/tests.rs`.
