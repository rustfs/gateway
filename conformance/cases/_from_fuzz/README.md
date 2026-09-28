# Fuzz-found case drafts

`fuzz-to-case` (in `rustfs-gateway-difftest`, rustfs/backlog#1762) writes a draft here when the `decode_diff` fuzz target finds the gateway and the pinned s3s routing the same request to different operations:

```bash
cargo +nightly fuzz run decode_diff fuzz/corpus/decode_diff fuzz/seeds/decode_diff
cargo +nightly fuzz tmin decode_diff fuzz/artifacts/decode_diff/crash-<hash>
cargo run -p rustfs-gateway-difftest --bin fuzz-to-case -- fuzz/artifacts/decode_diff/minimized-from-<hash> --write
```

A draft asserts what the gateway answered (status and error code) for the request exactly as the fuzz property read it, and carries `FUZZ-DRAFT` where a person must write: the title, the rationale and the evidence. It is not a case yet, and `scripts/check_fuzz_case_drafts.sh` fails while one is committed. To keep the difference watched for good:

1. Decide which stack is right, and write the rationale and the evidence (`conformance/cases/README.md`).
2. Move the file to the domain directory its behaviour belongs to, under that domain's next id, and add its row to `conformance/baseline.json`.
3. Register the difference in `crates/difftest/known-diffs.toml` with a matrix row that reproduces it, or fix the stack that is wrong.

`naming/c-naming-0033` is the first case made this way.
