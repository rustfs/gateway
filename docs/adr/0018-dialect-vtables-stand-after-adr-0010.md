# ADR-0018: The dialect vtable decision of ADR-0007 stands; ADR-0010 replaced only its request layout

- Status: Accepted
- Date: 2026-09-10
- Trigger: crate boundary — which decision governs dialect XML fields across types, codegen and the dialect crates
- Supersedes / Superseded by: none

## Context

ADR-0007 carries `Status: Superseded by ADR-0010`, and the index in `docs/adr/README.md` repeats
it. ADR-0010, *Box the public DTO inside handler requests*, says in its own Context what it
replaced: ADR-0007 had measured the inline handler request at 136 bytes and concluded the request
need not change, and that conclusion — ADR-0007's Q6 — predated the accepted DTO policy. ADR-0010
says nothing about the decision ADR-0007 exists for: one generated codec plus runtime `ExtField`
vtables for registered dialect elements, a borrowed `CodecPolicy` passed into decode and encode,
extension values in a TypeId-indexed map, known-sibling insertion slots, and the persistence
boundary that goes with them.

Read at the header level, the two documents say the vtable mechanism was retired. It was not, and
the reading is load-bearing: rustfs/backlog#1719 (lifecycle `DelMarkerExpiration`) is that
mechanism's first real user, and an agent closing it took the header at face value and concluded
the mechanism was dead rather than unbuilt (rustfs/gateway#220 records the wrong premise it
cost). `scripts/check_adr_contract.sh` allows exactly one lifecycle transition for a merged ADR —
`Accepted` to `Superseded by` a new ADR — and freezes every other byte, so ADR-0007's header
cannot be amended to say "Q6 only"; the guard's own shape for a correction is a new record.

## Decision

The decision of ADR-0007 remains in force in full except for its Q6 finding: dialect XML
elements are carried by runtime `ExtField` vtables registered against a borrowed `CodecPolicy`,
never by a second generated codec, a process-global registry, or a policy stored in `Req<O>`.
ADR-0010 supersedes Q6 — the layout of the handler request — and nothing else. A reader who
finds ADR-0007 marked superseded reads this record next and treats ADR-0007's Decision, Evidence
and Rejected alternatives as current. We will not amend ADR-0007's header, and we will not
re-decide the vtable mechanism here.

## Evidence

The mechanism ADR-0007 decided is the mechanism in the tree, on Rust 1.97.1 at `main`
17384a18 (2026-09-10): `crates/types/src/ext.rs` declares `pub trait ExtField` (line 34) and
`pub struct CodecPolicy` (line 136) and documents itself as "typed extension vtables, borrowed
per-codec policy, deterministic known-sibling insertion"; `crates/dialect-minio/src/lib.rs`
imports `CodecPolicy`, `ExtError`, `ExtField` and `PersistedXml` from it and is the dialect
crate that mechanism was decided for; `crates/model/src/ir/mod.rs`, `crates/types/src/cors_tagging.rs`
and `crates/types/src/persistence/lifecycle.rs` consume the same module. ADR-0010's Context names
the 136-byte measurement and its conclusion as the thing it replaced, and its Decision changes the
storage of `O::Input` inside `Req<O>` only. `grep -rn "ExtField\|CodecPolicy" crates/*/src` is
the command; five files is the count. The wrong premise this ADR exists to prevent is recorded
verbatim at https://github.com/rustfs/backlog/issues/1719#issuecomment-5346955563 `[inferred:
that the header was the cause is the agent's own account]`.

## Rejected alternatives

- Amending ADR-0007's status to `Accepted` with a note that only Q6 was replaced: rejected
  because `check_adr_contract.sh` permits no such transition for a merged ADR and no
  partial-supersession spelling exists in its grammar; adding one would widen the contract for
  every ADR to fix one header.
- Re-pointing ADR-0007's relation at a new ADR that restates the vtable decision as its own: rejected
  because it would make the vtable decision appear to have been re-taken in 2026-09 when it was
  taken in 2026-08 and never changed, and every reference to ADR-0007 in code comments would go
  stale for no change in behaviour.
- Fixing the index row alone: rejected because the index is derived from the header and the guard
  compares them; the row cannot disagree with the record it indexes.

## Consequences

ADR-0007's header keeps reading `Superseded by ADR-0010`, and this record is where a reader learns
what that supersession covers. A change to the `ExtField` mechanism is a change to ADR-0007's
decision and needs an ADR that supersedes ADR-0007 for that reason, not a note here. The guardrail
is the existing one: `scripts/check_adr_contract.sh` requires this record's five sections and its
bidirectional relation metadata, and `docs/adr/**` stays a Protected File so neither this record
nor ADR-0007 can be edited outside the Breaking Change process. Nothing downstream changes.
