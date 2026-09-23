# Third-party notices

## AWS service models

This repository vendors the S3 and STS service models from
[aws/api-models-aws](https://github.com/aws/api-models-aws) under the Apache
License 2.0.

Copyright Amazon.com, Inc. or its affiliates.

The vendored files are `model/s3.json` and `model/sts.json`. Their exact
upstream paths, pinned commit, checksums, and retrieval date are recorded in
`model/PROVENANCE.md`.

## Smithy timestamp format test suite

This repository vendors the timestamp compatibility corpus from
[smithy-lang/smithy-rs](https://github.com/smithy-lang/smithy-rs) under the
Apache License 2.0. The exact source revision and digest are recorded in
`crates/types/tests/data/README.md` and the root `NOTICE`.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

## Smithy signing test suite

The signing-suite runner consumes the external
[smithy-rs](https://github.com/smithy-lang/smithy-rs) corpus under the Apache
License 2.0. The suite is not vendored; the external runner accepts only commit
`cb39d6e52459b47fa8881a241ac9f78849f1bc25`. Its reviewed tree identities,
license blob, and complete case census are recorded in
`spec/third-party/aws-signing-test-suite.lock`.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

## External acceptance suites

The three entries below are the licence review behind
`.github/workflows/e2e-s3tests.yml`, `.github/workflows/e2e-mint.yml`, `ci/s3tests/`
and `ci/mint/`. Each records the licence,
**how that licence was verified rather than only what it says**, and the pin.
`scripts/check_third_party_doc.sh` asserts every row stays here and stays
complete; `scripts/check_no_vendored_suites.sh` asserts none of the source ever
lands in this tree.

### Ceph s3-tests

- Upstream: <https://github.com/ceph/s3-tests>
- Licence: **MIT**
- Vendored: **no.** The suite is cloned at run time into a scratch directory
  outside the repository, at the commit pinned in `ci/s3tests/pins.env`.
- Pin: commit `5522d1c351f75bc00ae0f64f742f3f095f5939d9`
- Verified 2026-09-02, by running each of these and reading the output:
  - `gh api repos/ceph/s3-tests --jq .license.spdx_id` → `MIT`
  - `git ls-remote https://github.com/ceph/s3-tests master` → the pinned commit
  - `git ls-remote --tags https://github.com/ceph/s3-tests` → **no output.**
    The project has never published a tag or a release, which is why the pin is
    a commit and not a version.
- Python dependencies: the suite's `requirements.txt` has no upper bounds, so its
  client is locked separately in `ci/s3tests/requirements.lock` (exact versions
  and sha256 hashes, compiled for Python 3.12 on 2026-09-14) and installed with
  `pip install --require-hashes --no-deps`. Those packages are downloaded at run
  time into a scratch virtual environment and are not redistributed.

Copyright the Ceph authors.

### MinIO mint

- Upstream: <https://github.com/minio/mint>
- Licence: **Apache-2.0** — not the server's licence, and worth stating because
  the assumption that it inherits one is the reason this suite gets skipped.
- Repository status: **archived** (read-only; last push 2026-01-08). Its bundled
  SDK suites are therefore frozen and will receive no upstream fix, which is why
  `.github/workflows/e2e-mint.yml` is scheduled evidence and never a blocking gate.
- Vendored: **no.** Run as a container image, pinned by digest and never by a
  tag: an archived repository's image tags can still be re-pointed.
- Pin: image `docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200`,
  the `edge` build of 2026-01-08 and a single-platform linux/amd64 manifest. The
  runner pulls exactly this digest; `ci/mint/pins.env` records it with the SDK
  census.
- Verified 2026-09-02:
  - `gh api repos/minio/mint --jq .license.spdx_id` → `Apache-2.0`
  - `gh api repos/minio/mint --jq .archived` → `true`
- Pin verified 2026-09-12:
  - `docker buildx imagetools inspect minio/mint:edge` → the digest above, as a
    single-platform manifest
  - `docker buildx imagetools inspect minio/mint:edge --format '{{json .Image}}'`
    → `"architecture": "amd64"`, `"os": "linux"`
  - `curl -s 'https://hub.docker.com/v2/repositories/minio/mint/tags?page_size=30'`
    → exactly two tags, `latest` (2024-05-28) and `edge` (2026-01-08)

Copyright the MinIO authors.

The producer patch tool in `ci/mint/patch_producers.py` operates on externally
acquired files and preserves their copyright and licence headers. It does not
vendor the suites or establish a new distributed image pin. Its reviewed source
shapes are:

- [MinIO .NET 7.0.0 logger](https://github.com/minio/minio-dotnet/blob/ac5dc79dfdd35b425f98233f55f8227aa705afb9/Minio.Functional.Tests/MintLogger.cs):
  Apache-2.0; edits retain test identity and error details while making the SDK
  name stable and JSON property names compatible with the strict reporter.
- [Mint .NET launcher](https://github.com/minio/mint/blob/12559d50625b722d11fd798ae8ac2fb204e66dd1/run/core/.minio-dotnet/run.sh):
  Apache-2.0; only the executable path changes.
- [mc functional runner](https://github.com/minio/mc/blob/7394ce0dd2a80935aded936b09fa12cbb3cb8096/functional-tests.sh):
  **AGPL-3.0-or-later**, as declared in that file; the Mint wrapper's Apache-2.0
  licence does not replace this header. Only uncaptured dependency diagnostics
  move to stderr; helper output used as failure evidence stays intact.

The derived image recipe in `ci/mint/Dockerfile` rebuilds the .NET functional
runner from the reviewed source archive. `ci/mint/dotnet-packages.json` pins the
complete NuGet archive closure, including self-contained runtime packs, before
an offline restore and build. The final image retains the MinIO LICENSE and the
licenses and third-party notices of the actual published dependencies under
`/opt/mint-dotnet/notices`.

`ci/mint/licenses/manifest.json` identifies each shipped package and the required
notice members of its verified archive. Where an archive omits its license text,
the manifest records the exact upstream repository commit, path, and SHA-256 of
the retained file; that commit must match the package's source metadata. The
collector refuses changed dependency identities, missing notices, and altered
notice bytes. `sources.json` accompanies the notices in the image. Build-only
analyzers are not copied into the final image. All three modified upstream
producer files carry a dated modification notice as well as their original
copyright and license headers.

### MinIO server

- Upstream: <https://github.com/minio/minio>
- Licence: **AGPL-3.0**, and the repository is archived.
- Vendored: **no**, and the rule here is stronger than the other two rows: no
  part of it is read, ported, vendored or depended on. Wire behaviour compatible
  with it is reproduced clean-room, from the AWS S3 API documentation and this
  project's own measurements. `minio-go` (Apache-2.0) as a *client* test tool is
  unaffected by this and is safe.
- Verified 2026-09-02: `gh api repos/minio/minio --jq '.license.spdx_id, .archived'`
  → `AGPL-3.0`, `true`.
- Enforced by `scripts/check_no_minio_source.sh`; the boundary itself is
  `docs/adr/0001-licensing-and-provenance-boundary.md`.
