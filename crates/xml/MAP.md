# MAP — rustfs-gateway-xml

Agent entry point. File → responsibility → when you need to open it.

Holds no S3 type, knows no element name, and has no opinion about which member goes where. Every
name and every ordering is supplied by the caller, from IR data.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring and the re-export list. | First stop. |
| `src/write.rs` | `XmlWriter`: the declaration, elements, attributes, escaping, and the paired empty-element form. No formatting options, because both S3 shapes are byte-observable. Plus `strip_declaration`, the inverse of the one declaration this crate writes. | A response body byte is wrong, you need a new element form, or a body is carrying two declarations. |
| `src/read.rs` | `parse` and `parse_with_limits` into a bounded `XmlNode` tree, with body-byte, `DOCTYPE`, entity, depth, element and attribute refusals. Namespace prefixes are dropped, so a prefixed body and a bare one decode identically. | A request body is refused, or you are changing a ceiling. |
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
- **An empty element is written `<X></X>`, never self-closing, and there is no whitespace between
  elements.** Both are what S3 does and both are visible to a byte-exact conformance case, so
  neither is an option a caller can set the other way.
- **`strip_declaration` matches the exact prefix and never scans.** The one caller is the committed
  response, whose head already carried a declaration; a scanner that skipped "any prolog" would
  truncate a document whose first bytes were written by something else, and this crate wrote the
  bytes it is asked to trim, so the one form it emits is the one form worth recognising.
- **`finish` closes whatever is still open.** An encoder that returned early would otherwise emit a
  truncated document, which is the one failure a client cannot tell from a dropped connection.

## Verify

```bash
cargo test -p rustfs-gateway-xml
cargo clippy -p rustfs-gateway-xml --all-targets -- -D warnings
```
