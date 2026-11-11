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

//! Resident-memory readings and accepted-connection census for RSS calibration.
//!
//! Responsible for: reading process RSS and observing listener accepts around the first RSS wave.
//! NOT responsible for: interpreting reuse ratios, scheduling probes or enforcing reader deadlines.
//! Upstream: the server load fixture. Downstream: `ps` and actual listener acceptance metrics.

use rustfs_gateway_server::RunningServer;
use std::process::Command;

pub(super) struct Census<'a> {
    loaded: &'a RunningServer,
    control: &'a RunningServer,
    loaded_before: usize,
    control_before: usize,
}

impl<'a> Census<'a> {
    pub(super) fn begin(loaded: &'a RunningServer, control: &'a RunningServer) -> Self {
        Self {
            loaded,
            control,
            loaded_before: loaded.metrics.accepted_connections(),
            control_before: control.metrics.accepted_connections(),
        }
    }

    pub(super) fn assert_only_slow_readers(self, slow_readers: usize) {
        assert_eq!(
            self.loaded.metrics.accepted_connections() - self.loaded_before,
            slow_readers,
            "the RSS calibration wave must contain only slow-reader connections"
        );
        assert_eq!(
            self.control.metrics.accepted_connections() - self.control_before,
            0,
            "the RSS calibration wave must contain no control probes"
        );
    }
}

pub(super) fn rss_bytes() -> Option<usize> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kibibytes = String::from_utf8(output.stdout).ok()?.trim().parse::<usize>().ok()?;
    kibibytes.checked_mul(1024)
}
