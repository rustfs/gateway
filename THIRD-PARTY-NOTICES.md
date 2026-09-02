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
`.github/workflows/e2e-s3tests.yml` and `ci/s3tests/`. Each records the licence,
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

Copyright the Ceph authors.

### MinIO mint

- Upstream: <https://github.com/minio/mint>
- Licence: **Apache-2.0** — not the server's licence, and worth stating because
  the assumption that it inherits one is the reason this suite gets skipped.
- Repository status: **archived** (read-only; last push 2026-01-08). Its bundled
  SDK suites are therefore frozen and will receive no upstream fix, which is why
  the mint job, when it lands, must never become a blocking gate.
- Vendored: **no.** Run as a container image, pinned by digest and never by a
  tag: an archived repository still republishes `:latest`.
- Pin: recorded with the runner in a follow-up to rustfs/backlog#1764; the
  runner is not in this repository yet.
- Verified 2026-09-02:
  - `gh api repos/minio/mint --jq .license.spdx_id` → `Apache-2.0`
  - `gh api repos/minio/mint --jq .archived` → `true`

Copyright the MinIO authors.

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
