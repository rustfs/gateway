---
name: New S3 operation
about: Request support for an S3 operation that is not implemented yet
title: "[op] <OperationName>"
labels: new-operation
---

> Implementation of a new operation follows **one operation per file**:
> `ops/<snake_name>.rs` contains exactly one `impl Operation`, and any code
> shared with other operations is declared with a `//! Shares:` header.
> This is what makes operations a safe unit of parallel work — do not open a
> request that bundles several operations into one file.

## Operation

- **AWS operation name** (PascalCase, e.g. `SelectObjectContent`):
- **AWS API documentation URL**:

## Use case (one sentence)

<!-- What are you trying to do that is currently impossible? -->

## Client dependency

- Is a client already relying on it? Which one, and what does it do when the
  operation is missing (error message, fallback, hard failure)?

## Operation family

<!-- Families share request/response shapes and validation rules, so a new
     member of an existing family is much cheaper to implement. -->

- [ ] List
- [ ] Copy
- [ ] Conditional
- [ ] ACL
- [ ] Checksum
- [ ] None of the above / new family

## Notes

<!-- Anything already known about the wire shape: required query keys, headers,
     XML body. Link plus your own summary — do NOT paste AWS documentation text
     (copyright, see CONTRIBUTING.md). -->
