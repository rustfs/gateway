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
present and every acceptance case passes. The current census is 36 passed, 3 blocked, 39 total:
the historical writer matrix is absent (`g-d4-001` and `g-d5-001`, rustfs/backlog#2096), and
`g-d1-003` remains blocked by rustfs/backlog#2104. This strict gate is required for migration
closure, not for ordinary PR sample regression. Do not infer acceptance from a clean D1-D5 run.

Strict mode names one reason at a time: while a source is absent it reports
`ApprovedSourceAbsent`, even if every other row passed; once all sources are present it
reports `ClosureBlocked` with every remaining blocked case. Status zero requires both to clear.

## Resolving a blocker

Blockers are cleared by evidence, never by editing the verdict:

- **Historical writer matrix (rustfs/backlog#2096).** Add a `SourceRegistration` row for
  `HistoricalWriterMatrix` to `SOURCE_REGISTRY` in `src/provenance.rs`, naming a writer and an
  exact version, with witness digests that are real samples in the built corpus. Once the source
  is present, `g-d4-001` and `g-d5-001` must become passed rows with an evidence probe in
  `production_registry()` (`src/acceptance_census.rs`): a still-blocked row is rejected as
  `InvalidBlocker`. Strict mode then reports `ClosureBlocked(["g-d1-003"])`.
- **`g-d1-003` (rustfs/backlog#2104).** Replace its blocked row with a passed row and a probe,
  and remove its entry from `required_blocker`.

The current counts are pinned on purpose, so they have to be updated in the same change:
`tests/cli.rs`, `src/acceptance_census/tests.rs`, and the sample totals in `src/bin/four-way.rs`
and `src/corpus/backup_zip.rs`.
