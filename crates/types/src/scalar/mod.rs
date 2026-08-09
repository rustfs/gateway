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

//! The S3 scalar vocabulary: the leaf types every generated dto is built from.
//!
//! Responsible for: the `type.kind` variants the frozen IR names — `ETag`, `Checksum`,
//! `ChecksumSpec`, `Timestamp`, `OpaqueString`, `ObjectKey`, `BucketName`, `Range` — plus the
//! error-code vocabulary and its HTTP status table. Each of them turns a protocol exception that
//! would otherwise be an `if` inside a serialiser into a value: a rendering context, a timestamp
//! format, a table row.
//! NOT responsible for: reading or writing the wire (headers, XML, query strings are
//! `rustfs-gateway-http` / `rustfs-gateway-xml`), deciding *where* in the pipeline a value is validated (that is
//! the P3 ingest pipeline), and IO of any kind.
//! Upstream: nothing inside this workspace — this is the bottom of `rustfs-gateway-types`. Downstream:
//! the generated dto layer, and through it every operation family.
//!
//! # The one rule that shapes this module
//!
//! Axiom A2: a wire representation is never a default. `ETag` has no `Display`, `Timestamp` has no
//! `Display`; both take the context or the format as an argument, so "forgot the quotes" and
//! "used ISO 8601 where the header wants an HTTP date" are not writable, rather than merely
//! discouraged.

mod base64;
mod checksum;
mod error_code;
mod error_status;
mod etag;
mod name;
mod naming;
mod opaque_string;
mod parse_error;
mod range;
mod timestamp;

#[cfg(test)]
mod tests;

pub use self::checksum::{
    ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType, Checksummer, ContentMd5, parse_request_checksum,
};
pub use self::error_code::ErrorCode;
pub use self::error_status::{ErrorContext, mask_for_authorization, status_of};
pub use self::etag::{ETag, EtagRender};
pub use self::name::{BucketName, ObjectKey, is_xml_representable, validate_bucket_name, validate_object_key};
pub use self::naming::{
    AwsNameValidator, NamePolicy, NameRejection, NameValidator, SlashPolicy, Stricter, aws_bucket_rules, decode_once,
    floor_check_bucket, floor_check_key,
};
pub use self::opaque_string::OpaqueString;
pub use self::parse_error::{ParseError, rules};
pub use self::range::{ByteRange, RangeOutcome, RangeParse, RangeSpec};
pub use self::timestamp::{Timestamp, TimestampFormat};
