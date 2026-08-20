# MAP — rustfs-gateway-xml

Agent entry point. File → responsibility → when you need to open it.

Holds no S3 type, knows no element name, and has no opinion about which member goes where. Every
name and every ordering is supplied by the caller, from IR data.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and the re-export list. | First stop. |
| `src/chars.rs` | `is_xml_representable` / `is_xml_char`: the `Char` production of XML 1.0 §2.2, as one predicate, plus the `U+FFFD` the writer substitutes for a character that fails it. Re-exported by `rustfs-gateway-types`, so the workspace has exactly one answer. | A value is refused as `ForbiddenCharacter`, or you are asking which characters a document may hold at all. |
| `src/write.rs` | `XmlWriter`: the declaration, elements, attributes, escaping, and the paired empty-element form. No formatting options, because both S3 shapes are byte-observable. Plus `strip_declaration`, the inverse of the one declaration this crate writes. | A response body byte is wrong, you need a new element form, or a body is carrying two declarations. |
| `src/read.rs` | `parse` and `parse_with_limits` into a bounded `XmlNode` tree, with body-byte, `DOCTYPE`, entity, depth, element and attribute refusals. Element prefixes are dropped, so a prefixed body and a bare one decode identically; attribute prefixes are *resolved*, so `XmlNode::attribute_ns` answers by namespace. | A request body is refused, an attribute is not reaching a decoder, or you are changing a ceiling. |
| `src/error.rs` | `XmlError`, one variant per refusal. No variant carries a fragment of the input. | You are mapping a refusal onto an S3 error code. |
| `src/tests.rs` | Writer byte-shape controls and a negative-majority reader matrix, including the P3-05 XML limit cases. | Before changing either half. |

## Shape decisions worth not re-litigating

- **A `DOCTYPE` is refused, not skipped.** `quick-xml` does not expand entities, so skipping would
  be safe today — which is exactly the safety that disappears in a dependency bump nobody reviews
  as a protocol change.
- **Entities are resolved here, by name.** `quick-xml` hands every `&…;` back verbatim; the five
  XML predefines and numeric character references are resolved and every other reference is
  refused. Nothing else decides what `&xxe;` means.
- **Depth and element count are bounded separately from body bytes.** A cap on bytes does not bound
  the tree a body can describe.
- **An attribute is keyed by its namespace, never by its prefix, and a `xmlns:` declaration is not
  an attribute.** A prefix is a document-local alias: `xsi:type` and `xs:type` are the same
  attribute when both prefixes are bound to the XMLSchema-instance namespace, and `xsi:type` in a
  document that never bound `xsi` is not that attribute at all — it is dropped rather than stored
  in no namespace, because storing it there would make it indistinguishable from an unprefixed
  `type=`. `<Grantee>` is the one element in the S3 surface this matters for.
- **An empty element is written `<X></X>`, never self-closing, and there is no whitespace between
  elements.** Both are what S3 does and both are visible to a byte-exact conformance case, so
  neither is an option a caller can set the other way.
- **`strip_declaration` matches the exact prefix and never scans.** The one caller is the committed
  response, whose head already carried a declaration; a scanner that skipped "any prolog" would
  truncate a document whose first bytes were written by something else, and this crate wrote the
  bytes it is asked to trim, so the one form it emits is the one form worth recognising.
- **The character range is one predicate, applied at both ends.** The reader refuses a document
  carrying a character XML 1.0 cannot represent; the writer substitutes `U+FFFD` rather than
  emitting one. Two predicates would drift, and the direction that matters is accepting on the way
  in what the writer then writes raw — which produces a response no conforming parser accepts, so
  one bad value hides every other value in the document. See `docs/protocol-hazards.md` and
  rustfs/gateway#256. The writer substitutes rather than refuses for the same reason `finish`
  closes rather than returning early.
- **`finish` closes whatever is still open.** An encoder that returned early would otherwise emit a
  truncated document, which is the one failure a client cannot tell from a dropped connection.

## Verify

```bash
cargo test -p rustfs-gateway-xml
cargo clippy -p rustfs-gateway-xml --all-targets -- -D warnings
```
