# MAP — s3gate-types

Agent entry point. File → responsibility → when you need to open it.

## Crate root

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Crate docs and the public re-export list. | You need to know what this crate exports. |
| `src/scalar/mod.rs` | Module wiring for the scalar vocabulary, and the axiom that shapes it (no default rendering). | Adding a scalar, or working out where one lives. |

## The scalars

| File | Responsibility | Read it when |
|---|---|---|
| `src/scalar/etag.rs` | `ETag`: one normalised opaque tag, three explicit rendering contexts, weak/strong comparison, the `*` wildcard, the multipart `-N` form. No `Display`, no `Into<String>`. | Anything touches an entity tag, a precondition header, or a multipart tag. |
| `src/scalar/checksum.rs` | The five checksum algorithms, `ChecksumSpec` (packed, ≤96 bytes), `Content-MD5`, the `Checksummer` trait, part combination, and `parse_request_checksum` header selection. | Adding an integrity check, or debugging which error code a checksum failure produces. |
| `src/scalar/base64.rs` | Strict RFC 4648 §4 base64, private to this crate. | A checksum value is being rejected and you suspect the encoding. |
| `src/scalar/timestamp.rs` | `Timestamp` plus the four IR formats. Hand-written calendar arithmetic; no `Display`. | Binding a dated field, or a date is off by an hour, a day, or a century. |
| `src/scalar/opaque_string.rs` | `OpaqueString`: echoed byte for byte. `Expires` uses it. | Somebody proposes parsing `Expires` as a date. Read it before agreeing. |
| `src/scalar/name.rs` | `ObjectKey` (never normalised, keeps the encoded spelling) and `BucketName` plus the default AWS rules. | Touching routing, authorization, or anything that compares a key. |
| `src/scalar/range.rs` | `ByteRange` / `RangeParse` / `RangeOutcome`: parse, classify, resolve against a length, render `Content-Range`. | Implementing a ranged read, or deciding between 200, 206 and 416. |
| `src/scalar/error_code.rs` | `ErrorCode` (newtype over `Cow`) and the full code → status table, declared by one macro so a constant and its row cannot drift apart. | Adding an error code, or checking which status one maps to. |
| `src/scalar/error_status.rs` | `ErrorContext`, `status_of`, `mask_for_authorization` — the request facts that change an error's outcome. | An error's status or code depends on who is asking or where the bucket lives. |
| `src/scalar/parse_error.rs` | `ParseError` and the `rules` identifiers every diagnostic quotes. | Writing a new validation and choosing its rule reference. |

## Tests

`src/scalar/tests/` holds one module per scalar. Test names carry the conformance case id
(`c_etag_n003_…`) where one exists, so a failing case in the suite leads straight to the unit test
that covers the same rule. Negative cases outnumber positive ones by design.

## Things that will bite you

- **`ETag` has no `Display` and no `Into<String>`.** That is deliberate; call `render(ctx)`. If a
  call site does not know its context, the context is missing from the caller, not from the type.
- **`Timestamp` has no `Display` either**, for the same reason: pick the format.
- **`ObjectKey` never normalises.** Do not add "helpful" collapsing of `//` or `..`. Authorization
  and storage must see identical bytes.
- **The IR calls the range type `Range`; the Rust type is `ByteRange`**, to stay clear of
  `std::ops::Range`.
- **An unknown `ErrorCode` maps to 400, never 500.** If you are tempted to change the fallback,
  read the reasoning in `error_code.rs` first.
- **`crc-fast` must keep `default-features = false`** in `Cargo.toml`; the comment there says why.
