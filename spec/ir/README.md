# Operation IR documents

The operation IR is the generated contract between model lowering and every codegen backend:

```text
model/s3.json + model/overlays/*.toml -> IR -> spec/, OPERATIONS.md, generated/
```

`model/overlays/*.toml` is the only hand-written protocol source. Files under `spec/ir/` are
generated, except `samples/*.json`, which are hand-written goldens used to review codegen output.

Validate the schema and the three goldens with:

```console
cargo xtask ir validate
```

The negative corpus contains mutation descriptors. Each descriptor starts from one golden, applies
one JSON Pointer mutation, and states the diagnostic pointer and rule that must result. Run it with:

```console
cargo xtask ir validate --expect-fail spec/ir/samples/invalid
```

Adding a schema field requires updating every sample, validator semantic check, and consumer. A
breaking shape change also requires an `ir_version` bump, the protected-file process, migration
notes, and a new `IR-FREEZE: approved` review.
