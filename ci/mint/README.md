# Building a Mint candidate

The source recipe rebuilds the missing .NET functional runner and corrects the
`mc` dependency diagnostics in the pinned Mint image. It preserves all fifteen
SDK directories. Every `e2e-mint` run, scheduled or manual, in either mode,
builds this recipe on the `pins.env` digest and measures the result
(rustfs/gateway#720): the pinned image alone ships no .NET runner and writes a
non-JSON line into `mc`'s log, so neither SDK could be judged without it.

From the repository root, build a Linux amd64 candidate and pass its exact local
image identity to the record runner:

```sh
cargo build --release -p rustfs-gateway-compat-sut
docker build --platform linux/amd64 --progress plain \
  --iidfile /tmp/mint-candidate.id ci/mint
ci/mint/run.sh --mode record --local-image "$(cat /tmp/mint-candidate.id)" \
  --work /tmp/mint-work --out /tmp/mint-out
```

The workflow builds the image on its native amd64 runner and uploads only the
aggregate report. It never publishes the image.

The workflow adds `--build-arg MINT_REGISTRY=mirror.gcr.io`: anonymous Docker
Hub pulls from the shared runner pool are rate-limited (run 36520382963 failed
on `429 Too Many Requests`). The argument moves only where the pinned digest is
fetched from; a pull by digest is verified against it, so the bytes are the
same. Pass it locally too if Docker Hub refuses or cannot be reached.

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

The raw SDK logs never leave the runner, so the aggregate names each failing
function with a class drawn from its record's `error`: `function:<exception>/<status>/<code>`,
for example `S3Client.putObject versions:S3Exception/400/-`. The exception is the first
`...Exception` or `...Error` token, the status is the number after `Status Code`, and the code is
the S3 error code where the text puts one in a defined place; each is `-` where the text names
none. Nothing else of the text is carried. The class says which failure it was and not where in
the test it happened; a failure that stays `-/-/-` is one the grammar cannot read, and the answer
is a wider grammar, never a wider baseline.
