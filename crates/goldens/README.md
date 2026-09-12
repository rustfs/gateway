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
