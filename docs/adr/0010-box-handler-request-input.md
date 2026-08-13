# ADR-0010: Box the public DTO inside handler requests

- Status: Accepted
- Date: 2026-08-13
- Trigger: handler request size and public DTO SemVer policy
- Supersedes / Superseded by: ADR-0007

## Context

Public generated DTO fields must remain directly constructible with `Default` and functional
update syntax. Large operation inputs therefore cannot be made smaller by hiding or splitting
those fields. Keeping the entire input inline in `Req<O>` also carries that layout through async
handler futures. ADR-0007 measured the former inline request at 136 bytes on a 64-bit target, but
its conclusion that the request need not change predated the accepted DTO policy.

## Decision

Store `O::Input` in one `Box` inside `Req<O>`. Keep the generated DTO surface unchanged. Keep a
136-byte ceiling and a separate 32-byte exact snapshot on 64-bit targets so the ceiling is not
reported as the observation. Because allocation makes `Req::new` non-const, downstream const or
static request construction must move to runtime or lazy initialization.

## Evidence

With Rust 1.97.1 on `aarch64-apple-darwin`,
`cargo test -p rustfs-gateway-core --test integration dto_cold_split -- --nocapture` measured
`Req<PutObject>` at 32 bytes. Removing the box made both the 136-byte ceiling and the 32-byte exact
snapshot fail at compile time. The same test constructs the public `PutObjectInput` with functional
update syntax and recovers the identical DTO from the request.

## Rejected alternatives

- Hiding or splitting public DTO fields breaks the accepted downstream construction contract.
- Checking only `<= 136` confuses a limit with an observation and does not prove the box remains.
- Keeping the input inline preserves const construction but returns the request to 136 bytes.

## Consequences

Each handler request allocates once for its input. `Req::new` is no longer const, so downstream
const and static request values require runtime or lazy construction. The core and facade versions
advance for that migration; the types version advances for the new protected field-count ratchet.
The exact request test, its box-removal mutation, and `generated/dto/field_counts.txt` guard these
contracts.
