// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The command line's usage text.
//!
//! Responsible for: the one place every option and exit code is spelled for a reader.
//! NOT responsible for: parsing any of it.
//! Upstream: `super`. Downstream: stdout, on `--help` or a usage error.

/// The usage text, also printed on a command-line error.
pub const USAGE: &str = "\
usage: rustfs-gateway-conformance <command> [options]

commands:
  run                       load the corpus and run it against a target
  diff-transports           run both production drivers in parallel and compare every case result
  validate                  load the corpus and check it against the frozen schema and the
                            conventions, without touching a target; every case it accepts is
                            reported `validated`, never `passed`, because nothing was executed
  baseline                  print a baseline document for the current results
  audit-keys                run the corpus, then check that every key the frozen schema declares
                            is one this harness actually reads

options:
  --filter <glob>           select cases whose path or id matches (`etag/`, `*mpu*`, `c-sig-0001`)
  --transport <hyper|conn>  assembly path to inject (default hyper)
  --profile <aws|minio|strict>
                            the profile the target claims (default aws)
  --root <dir>              corpus directory holding case.schema.json
  --endpoint <http(s)-url>  external target (raw HTTP/1.1)
  --allow-external-fixtures
                            allow isolated owned bucket/object setup and automatic cleanup
  --ca-cert <pem-path>      additional CA certificates for an HTTPS endpoint
  --baseline <file>         tolerate the failures this file records; fail only on a regression
  --json <file>             write the machine-readable report
  --junit <file>            write a JUnit document
  --exclude-slow            leave `slow` cases out, as the pull-request gate does
  --shard <index>/<count>   run only this share of the selected cases, numbered in corpus order,
                            so <count> workers with the same options cover the selection once;
                            `diff-transports` hands it to both of its children
  -h, --help                print this text

exit codes: 0 ok, 1 regression against the baseline, 2 usage, 3 environment
";
