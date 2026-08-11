# Smithy timestamp format corpus

This directory vendors one compatibility-data file from
https://github.com/smithy-lang/smithy-rs. It is kept byte-for-byte identical to
the upstream artifact; gateway test logic is written independently.

| Field | Value |
|---|---|
| License | Apache-2.0 |
| Commit | `2744eb413935073aa43800e58e36268cd90b3a83` |
| Upstream path | `rust-runtime/aws-smithy-types/test_data/date_time_format_test_suite.json` |
| Local path | `crates/types/tests/data/date_time_format_test_suite.json` |
| Bytes | 152448 |
| SHA-256 | `95adad86782f37c5eff4601cccaeb76b5ef827121ad7b2f7030224d231a746bd` |

Upstream notice: Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

## Format mapping

This is a compatibility matrix, not a claim that the Smithy runtime and the frozen S3 wire
contract accept and emit identical bytes. Every upstream vector is consumed. Each successful
format vector is compared with its upstream bytes before any difference is classified. Of the
660 vectors, 442 retain exact output bytes or canonical instants, 77 date-time outputs project to
S3's fixed three millisecond digits, 72 Smithy-declared format errors remain errors, and 69
fractional HTTP-date inputs remain rejected. All 86 HTTP-date format outputs already match
exactly. The Smithy corpus declares no parse errors.

| Upstream section name | Gateway format |
|---|---|
| `date-time` | `TimestampFormat::Iso8601` |
| `epoch-seconds` | `TimestampFormat::EpochSeconds` |
| `http-date` | `TimestampFormat::HttpDate` |
| no upstream section | `TimestampFormat::Iso8601Basic` |

Offset inputs remain part of `Iso8601`; they do not add a fifth frozen format.
The basic form has its own gateway vector because this upstream corpus has no
matching section.
