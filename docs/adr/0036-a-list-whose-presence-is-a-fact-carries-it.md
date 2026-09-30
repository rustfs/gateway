# ADR-0036: A list whose presence is a fact of its own carries it

- Status: Accepted
- Date: 2026-09-30
- Trigger: ADR-0004 P1 (a container is never wrapped) meets a wire where it is wrong: an empty wrapped list and an absent one are two documents legacy RustFS stores and answers differently (rustfs/gateway#1078, #1148)
- Supersedes / Superseded by: none

## Context

ADR-0004 P1 stores every list bare: "an empty `Vec` and an absent list are the same fact on the
wire". That holds for a flattened list, which has no element of its own, and for most wrapped
lists. It does not hold for a wrapped list the legacy stack holds as an `Option`: `<TargetGrants/>`
and no `TargetGrants` element read there as `Some([])` and `None`, RustFS stores the first with the
empty element and the second without it, and its answers write them back the same way. A bare
`Vec` has one spelling for both, so the gateway either wrote an empty wrapper for a configuration
stored without the list (the seam answer findings for the logging grants and the website routing
rules) or, under the RustFS document reading, refused an empty wrapper rather than store it
differently (`rd-doc-0005`). The migration's constraint is that every conversion is lossless and
that nothing a client sees changes except to match legacy RustFS.

## Decision

This narrows ADR-0004 P1 for the members below and changes nothing else in it. A **wrapped list in an XML document that the legacy structure of the same name holds as an
`Option`, and that the gateway's model does not require**, carries its presence: its DTO member is
`Option<Vec<_>>`. `emit::dto::presence::carries_presence` decides it from the IR and the seam
generator's checked-in legacy facts, so the set follows the pinned legacy release rather than a
table: today the ACL grants, the logging grants, the website routing rules, a restore location's
grants and user metadata, inventory's optional fields, and the directory-bucket and annotation
listings. Every other list stays the bare container P1 makes it.

- Decoders: the member is `Some` exactly when the wrapper element is there, empty or not.
- Encoders: a set list writes its wrapper and entries. An unset list writes the empty wrapper every
  deployment has always written, except under the RustFS response layout
  (`write_responses_as_rustfs`), where it writes nothing, as legacy RustFS does.
- The seam converts `Option` to `Option` in both directions, and the persistence bridge stores and
  reads the empty element, so a present empty list crosses and is stored as legacy RustFS stores it.
- The RustFS document reading hands an empty wrapper over instead of refusing it.

## Evidence

- The legacy facts the seam generator checks in (under `crates/codegen/src/emit/seam/`)
  type each of these members `Option<Vec<_>>`; `presence_tests` in `rustfs-gateway-codegen` lists
  the set derived from them.
- The seam decode diff in `rustfs-gateway-difftest` hands an empty `TargetGrants` and an empty
  `RoutingRules` to both stacks and stores both configurations as the same bytes
  (`put-bucket-logging-empty-grants`, `put-bucket-website-empty-routing-rules`); the seam answer
  diff writes a logging configuration without grants and a website one without rules as the legacy
  writer does under the RustFS layout, byte for byte.
- The request-document parity battery in `rustfs-gateway-goldens` answers every emptied or
  entry-less wrapper of these lists as legacy RustFS does, which it refused before (`rd-doc-0005`).
- The conformance corpus passes unchanged: no answer of another deployment moves.

## Rejected alternatives

- Keep every list bare and omit an empty wrapper under the RustFS layout: exact for a list never
  set and wrong for one legacy RustFS stored empty, and wrong for a list RustFS always sets
  (`ListBuckets`' `Buckets`, answered `<Buckets></Buckets>` for an account with none).
- Refuse an empty wrapper (the RustFS reading's `rd-doc-0005`): fails closed, but refuses documents
  legacy RustFS stores.
- Mark the members in the model overlays: the fact is the legacy stack's, and the seam's legacy
  facts already state it for every structure, so a hand-written table would only restate them.

## Consequences

- The members above change type in the public DTOs, a breaking change for a caller that builds or
  reads them: wrap a list in `Some(..)`, and read one with `.iter().flatten()` or
  `.as_deref().unwrap_or_default()`.
- Every deployment but the RustFS profile answers byte for byte as before; the conformance corpus
  is the evidence.
- A list the legacy stack adds as an `Option` in a later pinned release joins the set when the
  facts are re-extracted; `presence_tests` in `rustfs-gateway-codegen` pins today's set.
