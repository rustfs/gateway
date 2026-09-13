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

//! Pinned-s3s observations for Accelerate and Request Payment persistence.
//!
//! Responsible for: invoking the old XML codec and projecting owned gateway-neutral structures and
//! decisions. NOT responsible for: production parsing or HTTP behavior. Upstream: pinned s3s.
//! Downstream: persistence goldens; deleted with the compat surface by P9-09.

use super::s3s::dto::{AccelerateConfiguration, BucketAccelerateStatus, Payer, RequestPaymentConfiguration};
use super::s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

use crate::persistence::{PersistedAccelerateConfiguration, PersistedRequestPaymentConfiguration};

use crate::compat::{CompatCodecError, S3sAccelerateObservation, S3sRequestPaymentObservation};

/// Parses Accelerate bytes with the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old decoder rejects the document or trailing bytes.
pub(crate) fn parse_s3s_accelerate(input: &[u8]) -> Result<S3sAccelerateObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = AccelerateConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let status = value.status.as_ref().map(|status| status.as_str().to_owned());
    Ok(S3sAccelerateObservation {
        enabled: status.as_deref() == Some(BucketAccelerateStatus::ENABLED),
        structure: PersistedAccelerateConfiguration { status },
    })
}

/// Serializes an Accelerate value with the pinned old persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old encoder refuses the value.
pub(crate) fn serialize_s3s_accelerate(value: &PersistedAccelerateConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = AccelerateConfiguration {
        status: value.status.clone().map(BucketAccelerateStatus::from),
    };
    serialize_old(&old_value)
}

/// Parses Request Payment bytes with the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old decoder rejects the document or trailing bytes.
pub(crate) fn parse_s3s_request_payment(input: &[u8]) -> Result<S3sRequestPaymentObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = RequestPaymentConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let payer = value.payer.as_str().to_owned();
    Ok(S3sRequestPaymentObservation {
        requester_pays: payer == Payer::REQUESTER,
        structure: PersistedRequestPaymentConfiguration { payer },
    })
}

/// Serializes a Request Payment value with the pinned old persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when the old encoder refuses the value.
pub(crate) fn serialize_s3s_request_payment(value: &PersistedRequestPaymentConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = RequestPaymentConfiguration {
        payer: Payer::from(value.payer.clone()),
    };
    serialize_old(&old_value)
}

fn serialize_old<T: Serialize>(value: &T) -> Result<Vec<u8>, CompatCodecError> {
    let mut output = Vec::with_capacity(128);
    let mut serializer = Serializer::new(&mut output);
    value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}
