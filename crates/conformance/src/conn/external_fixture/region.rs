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

//! External bucket-region normalization.
//!
//! Responsible for: validating a canonical fixture region, selecting the matching SigV4 scope,
//! and emitting CreateBucketConfiguration outside `us-east-1`. NOT responsible for: endpoint
//! discovery, request I/O, or bucket ownership. Upstream: `super`; downstream:
//! `crate::inprocess::sign_request` and CreateBucket.

use crate::inprocess::REGION;
use crate::sut::SutError;
use crate::value::Value;

#[derive(Clone, Debug)]
pub(super) struct FixtureRegion {
    name: String,
    create_body: Vec<u8>,
}

impl FixtureRegion {
    pub(super) fn parse(declared: Option<&str>) -> Result<Self, SutError> {
        let name = declared.unwrap_or(REGION);
        let valid = (3..=64).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && name.bytes().next().is_some_and(|byte| byte.is_ascii_lowercase())
            && name
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase());
        if !valid {
            return Err(SutError::Environment(format!(
                "external fixture region `{name}` is not safe or canonical for both signing and LocationConstraint"
            )));
        }
        let create_body = if name == REGION {
            Vec::new()
        } else {
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{name}</LocationConstraint></CreateBucketConfiguration>"
            )
            .into_bytes()
        };
        Ok(Self {
            name: name.to_owned(),
            create_body,
        })
    }

    pub(super) fn create_body(&self) -> &[u8] {
        &self.create_body
    }

    pub(super) fn sign_spec(&self) -> Value {
        Value::Table(vec![
            ("mode".to_owned(), Value::String("sigv4_header".to_owned())),
            ("credential".to_owned(), Value::String("valid".to_owned())),
            ("region".to_owned(), Value::String(self.name.clone())),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_east_1_omits_the_location_constraint() {
        for declared in [None, Some("us-east-1")] {
            let region = FixtureRegion::parse(declared).expect("default fixture region");
            assert!(region.create_body().is_empty());
        }
    }

    #[test]
    fn another_region_has_one_exact_location_constraint() {
        let region = FixtureRegion::parse(Some("us-west-2")).expect("canonical region");
        assert_eq!(
            region.create_body(),
            b"<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>"
        );
        assert_eq!(region.sign_spec().read("signSpec.region").and_then(Value::as_str), Some("us-west-2"));
    }

    #[test]
    fn an_ambiguous_or_unsafe_region_is_rejected() {
        for region in ["EU", "../us-west-2", "-us-west-2", "us-west-2-"] {
            assert!(FixtureRegion::parse(Some(region)).is_err(), "{region}");
        }
    }
}
