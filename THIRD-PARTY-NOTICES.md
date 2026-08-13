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
