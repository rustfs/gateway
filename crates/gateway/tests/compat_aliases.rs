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

//! Compile-time contracts for the input-parameterized request compatibility alias.
//!
//! Responsible for: proving `S3Request<Input>` and `Req<Operation>` are the same type.
//! NOT responsible for: adapting the output-parameterized legacy response or s3s DTO values.
//! Upstream: `HasOperation`. Downstream: RustFS usecase signatures during the P9 migration.

use rustfs_gateway::{
    Req, S3Error, S3Request, S3Result,
    dto::{PutObject, PutObjectInput},
};

/// c-hasop-0002: the compatibility name and operation request assign in both directions.
#[test]
fn s3_request_and_req_are_the_same_type() {
    fn req_to_alias(request: Req<PutObject>) -> S3Request<PutObjectInput> {
        request
    }

    fn alias_to_req(request: S3Request<PutObjectInput>) -> Req<PutObject> {
        request
    }

    let _: fn(Req<PutObject>) -> S3Request<PutObjectInput> = req_to_alias;
    let _: fn(S3Request<PutObjectInput>) -> Req<PutObject> = alias_to_req;
}

/// c-hasop-0003: the compatibility result keeps the facade error type.
#[test]
fn s3_result_is_the_facade_result() {
    fn result_to_alias(result: Result<(), S3Error>) -> S3Result<()> {
        result
    }

    fn alias_to_result(result: S3Result<()>) -> Result<(), S3Error> {
        result
    }

    let _: fn(Result<(), S3Error>) -> S3Result<()> = result_to_alias;
    let _: fn(S3Result<()>) -> Result<(), S3Error> = alias_to_result;
}
