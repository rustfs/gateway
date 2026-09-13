# rustfs-gateway-goldens

Fail-closed compatibility evidence for persistence migrations away from the pinned s3s codec.
The crate keeps old and new observations independent while checking compatible reads,
byte-identical writes, rollback reads, parser permissiveness, and runtime behavior.

Run the ordinary regression checks with:

```sh
cargo run -p rustfs-gateway-goldens --bin corpus-report
cargo run -p rustfs-gateway-goldens --bin four-way -- --all
```

The coverage report includes all 13 configuration families, the four approved sources, and all
39 P9-01 acceptance cases. Present-source rows validate the registered witnesses; they do not
claim that every required writer version has been collected. Missing sources and blocked cases
stay visible while valid sample regression checks return zero. Invalid evidence still fails.

For final migration acceptance, run the strict gate:

```sh
cargo run -p rustfs-gateway-goldens --bin corpus-report -- --require-closure
```

This calls `require_acceptance_closure()` and returns nonzero until every approved source is
present and every acceptance case passes. The current census is 38 passed, 1 blocked, 39 total.
All four sources are present, including the historical writer matrix with six writer versions
(rustfs/backlog#2096), and `g-d1-003` remains blocked by rustfs/backlog#2104, so strict mode
reports `ClosureBlocked(["g-d1-003"])`. This strict gate is required for migration closure, not
for ordinary PR sample regression. Do not infer acceptance from a clean D1-D5 run.

Strict mode names one reason at a time: while a source is absent it reports
`ApprovedSourceAbsent`, even if every other row passed; once all sources are present it
reports `ClosureBlocked` with every remaining blocked case. Status zero requires both to clear.

## Resolving a blocker

Blockers are cleared by evidence, never by editing the verdict:

- **Historical writer matrix (rustfs/backlog#2096) — collected.** Each writer version is one
  `SourceRegistration` in `src/historical_writer/data.rs`, bound by SHA-256 to raw exports under
  `corpus/historical-writers/` and to the capture receipts in its `manifest.json`. `g-d4-001` and
  `g-d5-001` are passed rows; withdrawing every writer row makes the source absent again, and those
  two rows then fail as `BlockedCasePassed`. Adding a writer means capturing it for real and
  registering its receipt and row together; a partial matrix is refused.
- **`g-d1-003` (rustfs/backlog#2104).** Replace its blocked row with a passed row and a probe,
  and remove its entry from `required_blocker`.

The current counts are pinned on purpose, so they have to be updated in the same change:
`tests/cli.rs`, `src/acceptance_census/tests.rs`, `src/historical_writer/tests.rs`, and the
sample totals in `src/bin/four-way.rs` and `src/corpus/backup_zip.rs`.
