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

//! Names crossing the seam from s3s, compiled once for every seam revision (rustfs/gateway#1610).
//!
//! Responsible for: building a bucket name or object key an s3s value carries, and saying, typed,
//! when a [`ConversionError`] is one of those two refusals.
//! NOT responsible for: the floors themselves (`crate::scalar::naming`), or the gateway → s3s
//! direction, which only spells a name the gateway already holds.
//! Upstream: `BucketName`, `ObjectKey`. Downstream: every seam revision's `leaf`, `put_object` and
//! `get_bucket_location`, and a host mapping a refusal to its own client error.

use std::sync::Arc;

use super::ConversionError;
use crate::{BucketName, NamePolicy, NameValidator, ObjectKey, SlashPolicy, Stricter};

/// The reasons the two name refusals carry. The text is the tag [`ConversionError::name_kind`]
/// reads, so no other refusal may spell either.
const BUCKET_BELOW_FLOOR: &str = "not a bucket name the gateway can write";
const KEY_BELOW_FLOOR: &str = "not an object key the gateway can write";

/// The name a seam conversion refused because it is below the gateway's floor, as
/// [`ConversionError::name_kind`] reports it.
///
/// A host converting a request it already admitted maps these to its own client errors; every
/// other [`ConversionError`] is a value the gateway shape cannot hold, which is the host's own
/// internal error.
#[derive(Clone, Copy, Debug)]
pub enum NameRefusal {
    /// A bucket name below the bucket floor: empty, outside 3..=63 bytes, a path separator, a
    /// traversal segment, a `%`, or a byte outside ASCII graphic.
    BucketName,
    /// An object key below the key floor: empty, longer than 1024 bytes, a NUL or a control
    /// character.
    ObjectKey,
}

impl ConversionError {
    /// Which name the conversion refused as below its floor, or `None` for every other refusal.
    #[must_use]
    pub fn name_kind(&self) -> Option<NameRefusal> {
        match self.reason {
            BUCKET_BELOW_FLOOR => Some(NameRefusal::BucketName),
            KEY_BELOW_FLOOR => Some(NameRefusal::ObjectKey),
            _ => None,
        }
    }
}

/// No opinion on any name: under it [`BucketName::materialize`] applies the floor alone.
struct FloorOnly;

impl NameValidator for FloorOnly {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, _key: &str) -> Stricter {
        Stricter::NoOpinion
    }
}

/// A bucket name an s3s value carries, under the bucket floor alone.
///
/// The value is one s3s already admitted on a request, or one the host stored and lists, so the
/// naming grammar is the host's and has already run; only what no deployment may hold is refused.
pub(crate) fn bucket_name(field: &'static str, value: &str) -> Result<BucketName, ConversionError> {
    BucketName::materialize(value, &NamePolicy::new(SlashPolicy::AwsPreserve, Arc::new(FloorOnly))).map_err(|_| ConversionError {
        field,
        reason: BUCKET_BELOW_FLOOR,
    })
}

/// An object key an s3s value carries, under the key floor [`ObjectKey::new`] applies.
pub(crate) fn object_key(field: &'static str, value: String) -> Result<ObjectKey, ConversionError> {
    ObjectKey::new(value).map_err(|_| ConversionError {
        field,
        reason: KEY_BELOW_FLOOR,
    })
}
