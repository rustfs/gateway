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

This calls `require_acceptance_closure()` and `require_oracle_admission()` and returns nonzero
until both hold. The P9-01 census is 39 passed, 0 blocked, 39 total: all four sources are present,
including the historical writer matrix with six writer versions (rustfs/backlog#2096), and
`g-d1-003` was narrowed by rustfs/backlog#2104. This strict gate is required for migration
closure, not for ordinary PR sample regression. Do not infer acceptance from a clean D1-D5 run.

Oracle admission repeats the whole D1-D5 run, and re-reads every rejected sample, under each s3s
revision a real RustFS build links (`rustfs_gateway_types::compat::OracleRevision`): the baseline
`9c4690d8` (1.0.0-rc.5-preview.2), the rollback target `bdcb6259` (1.0.0-rc.6) and the candidate
`f3e17541` (`main`). Every refusal boundary that moves under a revision must match a finding in
`src/oracle_admission.rs` exactly, and every registered finding must still reproduce. Today all
accepted samples pass under all three, and one boundary moves: rollback and candidate read
`Rule/BlockedEncryptionTypes`, which the production decoder refuses (rustfs/gateway#740). Strict
mode therefore exits nonzero, naming that finding under both revisions, until #740 is resolved.

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
- **`g-d1-003` (rustfs/backlog#2104) — resolved by narrowing.** The pinned s3s oracle (and the
  s3s revision RustFS ships) refuse unknown content inside `Rule`, `Expiration` and `Filter`, so
  the case now claims only what they read: an unknown subtree beside `Rule`, with ID, Status,
  Expiration.Days and Filter.Prefix kept. The row is bound by `AcceptedSamples` to the two pinned
  digests in `lifecycle.rs::UNKNOWN_TOP_LEVEL_SUBTREES`, which must be accepted D1-D5 samples;
  the nested forms stay in the shared refusal matrix. Nested leniency would be a production
  compatibility extension, not evidence this crate can claim.

The current counts are pinned on purpose, so they have to be updated in the same change:
`tests/cli.rs`, `src/acceptance_census/tests.rs`, `src/historical_writer/tests.rs`, and the
sample totals in `src/bin/four-way.rs` and `src/corpus/backup_zip.rs`.
