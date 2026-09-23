# Building a Mint candidate

The source recipe rebuilds the missing .NET functional runner and corrects the
`mc` dependency diagnostics in the pinned Mint image. It preserves all fifteen
SDK directories. The normal scheduled run continues to use `pins.env`.

From the repository root, build a Linux amd64 candidate and pass its exact local
image identity to the record runner:

```sh
cargo build --release -p rustfs-gateway-compat-sut
docker build --platform linux/amd64 --progress plain \
  --iidfile /tmp/mint-candidate.id ci/mint
ci/mint/run.sh --mode record --local-image "$(cat /tmp/mint-candidate.id)" \
  --work /tmp/mint-work --out /tmp/mint-out
```

Alternatively, manually dispatch `e2e-mint` with `mode=record` and
`derived_image=true`. The workflow builds the candidate on its native amd64
runner and uploads only the aggregate report. It does not publish the image or
change the baseline. A candidate is refused in ratchet mode.

The recipe fixes the Mint and .NET SDK images by digest, the .NET source archive
by commit and SHA-256, and all 26 NuGet archives by SHA-256. The archive closure
includes both implicit runtime packs as well as the dependencies in the two
NuGet lock files. Each archive is verified before restore can execute its build
targets. Restore and self-contained compilation use a fresh package cache and
run without network access. These are reproducible build inputs; the recipe does
not claim byte-identical image manifests across independent builds.

Producer patches require exact original source hashes and add modification
notices without removing original license headers. The final image retains the
MinIO LICENSE and dependency notices under `/opt/mint-dotnet/notices`. Notice
collection checks the actual published dependency census and archive digests;
missing or changed notices fail the build. The .NET source archive has
no Git metadata, so SourceLink reports that source-control information is absent;
this does not skip compilation or any functional test.

A successful build proves that the runner is present, not that its tests pass.
Review the complete aggregate and require attributable `.minio-dotnet` and `mc`
records before treating either exclusion as recovered. Keep the image-pin change
and baseline update in separate pull requests, as required by `pins.env`.
