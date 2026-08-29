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

//! Application-body transport planning for the plaintext HTTP/1.1 driver.
//!
//! Responsible for: consuming all owned body transport state and selecting kernel, copied-file or
//! ordinary payload delivery before the response head is committed.
//! NOT responsible for: writing bytes, response framing or recording an unobserved body path.
//! Upstream: the managed response body. Downstream: the response writer's concrete delivery path.

use std::io;

use rustfs_gateway_stream::Body;
#[cfg(unix)]
use rustfs_gateway_stream::{NoZeroCopy, RefusedBodyTransport, TransportCaps};

use super::metrics::ResponseFallbackReason;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
const SUPPORTED_KERNEL_TRANSFER_CAPS: TransportCaps = TransportCaps::SENDFILE;

pub(super) enum ApplicationBodyPlan {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    KernelFile(rustfs_gateway_stream::FileRegion),
    #[cfg(unix)]
    CopiedFile {
        source: rustfs_gateway_stream::CopiedFileBody,
        fallback: ResponseFallbackReason,
    },
    Payload {
        body: Body,
        fallback: ResponseFallbackReason,
    },
}

pub(super) fn plan_application_body(body: Body) -> io::Result<ApplicationBodyPlan> {
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    {
        match body.into_transport().try_into_file_region_for(SUPPORTED_KERNEL_TRANSFER_CAPS) {
            Ok(region) => Ok(ApplicationBodyPlan::KernelFile(region)),
            Err(refused) if refused.reason() == NoZeroCopy::NotFileBacked => {
                Ok(refused_application_body(refused, ResponseFallbackReason::NotFileBacked))
            }
            Err(refused) if refused.reason() == NoZeroCopy::VerificationObligationPresent => {
                Ok(refused_application_body(refused, ResponseFallbackReason::VerificationRequired))
            }
            Err(refused) => Err(io::Error::other(refused.reason())),
        }
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))))]
    {
        let refused = match body.into_transport().try_into_file_region_for(TransportCaps::empty()) {
            Err(refused) => refused,
            Ok(_) => return Err(io::Error::other("transport without kernel transfer accepted a file region")),
        };
        let fallback = match refused.reason() {
            NoZeroCopy::NotFileBacked => ResponseFallbackReason::NotFileBacked,
            NoZeroCopy::VerificationObligationPresent => ResponseFallbackReason::VerificationRequired,
            NoZeroCopy::TransportLacksSendfile => ResponseFallbackReason::PlatformUnsupported,
            reason => return Err(io::Error::other(reason)),
        };
        return Ok(refused_application_body(refused, fallback));
    }
    #[cfg(not(unix))]
    {
        Ok(ApplicationBodyPlan::Payload {
            body,
            fallback: ResponseFallbackReason::NotFileBacked,
        })
    }
}

#[cfg(unix)]
fn refused_application_body(refused: RefusedBodyTransport, fallback: ResponseFallbackReason) -> ApplicationBodyPlan {
    match refused.try_into_copied_file() {
        Ok(source) => ApplicationBodyPlan::CopiedFile { source, fallback },
        Err(refused) => ApplicationBodyPlan::Payload {
            body: refused.into_body(),
            fallback,
        },
    }
}
