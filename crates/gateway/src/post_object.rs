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

//! The narrow production bridge from a POST Object form to the ordinary typed pipeline.
//!
//! Responsible for: reading only bounded text parts before authentication, resolving the already
//! implemented SigV4/SigV2 POST-policy authority, and exposing the file as a policy-bounded live
//! stream after authentication, and applying the form's success action to a successful storage
//! result. NOT responsible for: signature comparison, authorization, or storage. Upstream:
//! `crate::service` after routing and governing. Downstream: the ordinary core decoder/handler
//! dispatch path.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::VecDeque;
use std::fmt;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use rustfs_gateway_http::{BodyIntegrity, FileReader, FileStep, FormGrammar, FormLimits, FormReader, FormReject, FormStep};
use rustfs_gateway_sig::{
    EmptyRegion, PostPolicy, PostPolicyError, PostPolicyLimits, RegionLength, RegionRule, RequestNow, ServiceReading,
    SigV2PostPolicy,
};
use rustfs_gateway_types::dto::{PostObjectFields, PostObjectInput};
use rustfs_gateway_types::{BucketName, NamePolicy, ObjectKey};

use crate::close::ConnectionIntent;
use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts, MetadataAdmission};
use crate::render::{S3Error, from_handler};
use crate::request_body::{BodyMonitor, StreamingRead};
use crate::wire_read::{WireFrames, WireProgress};
use crate::{ErrorCode, HandlerError, RequestBody, ResponseKind};

mod response;
use response::PostObjectResponsePlan;

enum AcceptedPolicy {
    SigV4(Box<PostPolicy>),
    SigV2(SigV2PostPolicy),
    Anonymous,
}

impl AcceptedPolicy {
    fn final_key<'a>(&'a self, anonymous_key: &'a str) -> &'a str {
        match self {
            Self::SigV4(policy) => policy.final_key(),
            Self::SigV2(policy) => policy.final_key(),
            Self::Anonymous => anonymous_key,
        }
    }

    fn read_ceiling(&self, limits: FormLimits) -> u64 {
        match self {
            Self::SigV4(policy) => policy.read_ceiling(),
            Self::SigV2(policy) => policy.read_ceiling(),
            Self::Anonymous => limits.max_file_bytes(),
        }
    }

    fn enforce_final(&self, bucket: &str, key: &str, file_bytes: u64) -> Result<(), PostPolicyError> {
        match self {
            Self::SigV4(policy) => policy.enforce_final(bucket, key, file_bytes).map(|_| ()),
            Self::SigV2(policy) => policy.enforce_final(bucket, key, file_bytes).map(|_| ()),
            Self::Anonymous => Ok(()),
        }
    }
}

/// A governed form whose text fields are in hand and whose first file byte remains unread.
pub(crate) struct PostObjectPrelude<B: Body> {
    reader: FormReader,
    frames: WireFrames<B>,
    first_file_bytes: Option<Bytes>,
    limits: FormLimits,
    timeouts: BodyTimeouts,
    /// The request's declared body length, from which the legacy grammar fixes the file's.
    declared_length: Option<u64>,
}

impl<B> PostObjectPrelude<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Reads the prelude under the gateway's own form grammar.
    #[cfg(test)]
    pub(crate) async fn read(
        body: Option<B>,
        content_type: &str,
        limits: FormLimits,
        timeouts: BodyTimeouts,
    ) -> Result<Self, S3Error> {
        Self::read_with_grammar(body, content_type, limits, FormGrammar::Gateway, timeouts).await
    }

    /// Reads the prelude, the form read under `grammar`.
    pub(crate) async fn read_with_grammar(
        body: Option<B>,
        content_type: &str,
        limits: FormLimits,
        grammar: FormGrammar,
        timeouts: BodyTimeouts,
    ) -> Result<Self, S3Error> {
        Self::read_form(body, content_type, limits, grammar, timeouts, form_refusal).await
    }

    pub(crate) async fn read_form(
        body: Option<B>,
        content_type: &str,
        limits: FormLimits,
        grammar: FormGrammar,
        timeouts: BodyTimeouts,
        refusal: fn(FormReject) -> S3Error,
    ) -> Result<Self, S3Error> {
        let Some(body) = body else {
            return Err(refusal(FormReject::MissingFile));
        };
        let progress = WireProgress::for_body(BodyDigestObligation::None, Some(&body));
        let mut frames = WireFrames::new(body, progress, BodyCeilings::streaming(None), timeouts);
        let mut reader = FormReader::with_grammar(content_type, limits, grammar).map_err(refusal)?;
        loop {
            let Some(frame) = core::future::poll_fn(|context| frames.poll_next(context)).await? else {
                return Err(refusal(reader.finish()));
            };
            match reader.push(&frame).map_err(refusal)? {
                FormStep::NeedMore => {}
                FormStep::FileReached { consumed } => {
                    let first_file_bytes = (consumed < frame.len()).then(|| frame.slice(consumed..));
                    return Ok(Self {
                        reader,
                        frames,
                        first_file_bytes,
                        limits,
                        timeouts,
                        declared_length: None,
                    });
                }
            }
        }
    }

    /// Records the request's declared body length. Under the legacy RustFS grammar with a declared
    /// length, the file part's exact length follows from it, as legacy RustFS derives it, and is
    /// handed to the handler as the body's length (rustfs/gateway#1167).
    #[must_use]
    pub(crate) fn with_declared_length(mut self, declared_length: Option<u64>) -> Self {
        self.declared_length = declared_length;
        self
    }

    pub(crate) fn form_fields(&self) -> Vec<(&str, &str)> {
        self.reader
            .fields()
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect()
    }

    pub(crate) fn policy_limits(&self) -> PostPolicyLimits {
        let mut limits = PostPolicyLimits::default();
        if matches!(self.reader.grammar(), FormGrammar::LegacyRustfs { .. }) {
            limits.max_encoded_bytes = self.limits.max_policy_bytes();
            limits.max_decoded_bytes = limits.max_encoded_bytes / 4 * 3;
            // Legacy RustFS bounds a policy's conditions only by the policy field's bytes
            // (rustfs/gateway#1173): every JSON element takes at least one decoded byte, so this
            // ceiling never refuses before the byte ceiling does.
            limits.max_json_elements = limits.max_decoded_bytes;
        }
        limits
    }

    pub(crate) fn resolve(
        self,
        bucket: BucketName,
        names: &NamePolicy,
        now: RequestNow,
    ) -> Result<ResolvedPostObject<B>, S3Error> {
        let policy_limits = self.policy_limits();
        let fields: Vec<(&str, &str)> = self
            .reader
            .fields()
            .iter()
            .map(|field| (field.name(), field.value()))
            .collect();
        // The RustFS profile stores what legacy RustFS stores from this form, or refuses it before
        // the file is read (`legacy`). A field this bridge cannot carry is refused only at the
        // hand-off, after authorization: every refusal legacy RustFS answers before it stores —
        // the signature, the policy, the success controls, authorization — keeps its own answer.
        let legacy_store = matches!(self.reader.grammar(), FormGrammar::LegacyRustfs { .. });
        let not_carried = if legacy_store {
            legacy::refuse_uncarried(&fields).err()
        } else {
            None
        };
        // What `${filename}` stands for: the `filename` parameter, or under the legacy RustFS
        // grammar the file part's own name when it carried none (`FormReader::file_name`).
        let filename = self.reader.file_name().unwrap_or_default();
        let has_policy = fields.iter().any(|(name, _)| *name == "policy");
        let policy = if fields.iter().any(|(name, _)| *name == "x-amz-algorithm") {
            // The widest reading: this runs after the authenticator verified the same credential
            // under the deployment's own region and service policy, so an empty or a long region,
            // or a service the RustFS profile verifies on every route, reaching here was read
            // there, and the conditions read below depend on neither.
            let rule = RegionRule::STRICT
                .with_empty(EmptyRegion::Admitted)
                .with_length(RegionLength::Unbounded)
                .with_services(ServiceReading::AnyName);
            AcceptedPolicy::SigV4(Box::new(
                PostPolicy::parse_with(&fields, filename, policy_limits, now, rule).map_err(policy_refusal)?,
            ))
        } else if fields.iter().any(|(name, _)| *name == "awsaccesskeyid") {
            let parse = if legacy_store {
                SigV2PostPolicy::parse_as_legacy_rustfs
            } else {
                SigV2PostPolicy::parse
            };
            AcceptedPolicy::SigV2(parse(&fields, filename, policy_limits, now).map_err(|reject| {
                if legacy_store && matches!(reject, PostPolicyError::Malformed | PostPolicyError::ConditionFailed) {
                    from_handler(
                        HandlerError::new(ErrorCode::INVALID_POLICY_DOCUMENT, "the POST policy was not accepted"),
                        ResponseKind::Other,
                        ConnectionIntent::MayKeepAlive,
                    )
                } else {
                    policy_refusal(reject)
                }
            })?)
        } else if has_policy {
            return Err(policy_refusal(PostPolicyError::Malformed));
        } else {
            AcceptedPolicy::Anonymous
        };
        let key_field = fields
            .iter()
            .find_map(|(name, value)| (*name == "key").then_some(*value))
            .ok_or_else(|| policy_refusal(PostPolicyError::Malformed))?;
        let anonymous_key = if matches!(policy, AcceptedPolicy::Anonymous) {
            key_field.replace("${filename}", filename)
        } else {
            key_field.to_owned()
        };
        let key_text = policy.final_key(&anonymous_key);
        let key =
            ObjectKey::materialize_decoded(key_text, names).map_err(|_| policy_refusal(PostPolicyError::ConditionFailed))?;
        let (metadata, content_type, object_fields) = if legacy_store {
            // Legacy RustFS's own refusal of an unreadable field answers before this bridge's.
            let object_fields = legacy::object_fields(&fields)?;
            legacy::refuse_other_key(key.as_str(), &legacy::stored_key(key_field, filename))
                .map_err(legacy::NotCarried::into_error)?;
            (legacy::metadata(&fields), legacy::content_type(&fields), object_fields)
        } else {
            let metadata = fields
                .iter()
                .filter_map(|(name, value)| {
                    name.strip_prefix("x-amz-meta-")
                        .map(|suffix| (suffix.to_owned(), (*value).to_owned()))
                })
                .collect();
            (metadata, None, PostObjectFields::default())
        };
        let response = PostObjectResponsePlan::parse(&fields, &bucket, &key, legacy_store)?;
        let ceiling = policy.read_ceiling(self.limits);
        let file_length = self
            .declared_length
            .and_then(|declared| self.reader.declared_file_length(declared));
        let file = self.reader.into_file(ceiling).map_err(form_refusal)?;
        Ok(ResolvedPostObject {
            frames: self.frames,
            first_file_bytes: self.first_file_bytes,
            file,
            file_length,
            policy,
            bucket,
            key,
            content_type,
            metadata,
            object_fields,
            response,
            not_carried,
            legacy_policy_errors: legacy_store,
            timeouts: self.timeouts,
        })
    }
}

/// A resolved POST Object request held between authentication and route authorization.
pub(crate) struct ResolvedPostObject<B: Body> {
    frames: WireFrames<B>,
    first_file_bytes: Option<Bytes>,
    file: FileReader,
    /// The file part's exact length, when the grammar and the declared body length fix it.
    file_length: Option<u64>,
    policy: AcceptedPolicy,
    bucket: BucketName,
    key: ObjectKey,
    /// The `Content-Type` field under the RustFS profile; `None` under the gateway grammar.
    content_type: Option<String>,
    metadata: Vec<(String, String)>,
    /// The other `PutObject` members the form set, under the RustFS profile; none under the
    /// gateway grammar.
    object_fields: PostObjectFields,
    response: PostObjectResponsePlan,
    /// Under the RustFS profile, why this form cannot be stored as legacy RustFS stores it.
    not_carried: Option<legacy::NotCarried>,
    legacy_policy_errors: bool,
    timeouts: BodyTimeouts,
}

impl<B> ResolvedPostObject<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(crate) fn key(&self) -> &ObjectKey {
        &self.key
    }

    pub(crate) fn response_plan(&self) -> PostObjectResponsePlan {
        self.response.clone()
    }

    pub(crate) fn handoff(self, _proof: &MetadataAdmission<'_>) -> Result<(RequestBody, Option<BodyMonitor>), S3Error> {
        // After authorization and before a file byte is read or the handler runs: the last point
        // at which legacy RustFS would have refused nothing and gone on to store.
        self.response.before_storage().map_err(policy_refusal)?;
        if let Some(refusal) = self.not_carried {
            return Err(refusal.into_error());
        }
        // A file whose exact length the declared body fixes is judged by the policy before the
        // handler runs, as legacy RustFS judges it on the length it derived; only the legacy
        // grammar fixes one, so the answer is legacy RustFS's (rustfs/gateway#1167).
        if let Some(length) = self.file_length {
            self.policy
                .enforce_final(self.bucket.as_str(), self.key.as_str(), length)
                .map_err(|error| self.frames.mark_refusal_if_unfinished(legacy_file_policy_refusal(error)))?;
            // An empty file is refused here too, before the handler, as legacy RustFS refuses the
            // upload it derived no length for (see `PostFileBody::complete`).
            if length == 0 {
                return Err(self.frames.mark_refusal_if_unfinished(legacy_empty_file_refusal()));
            }
        }
        let body = PostFileBody {
            frames: self.frames,
            first: self.first_file_bytes,
            initial: true,
            legacy_policy_errors: self.legacy_policy_errors,
            file: self.file,
            policy: self.policy,
            bucket: self.bucket.as_str().to_owned(),
            key: self.key.as_str().to_owned(),
            ended: false,
            pending: VecDeque::new(),
        };
        let opened = StreamingRead::new_with_refusal(
            Some(body),
            (self.file_length, None),
            (BodyCeilings::streaming(None), self.timeouts, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
            PostBodyError::into_refusal,
        )?;
        let (stream, monitor) = opened.into_parts();
        Ok((
            RequestBody::PostObject(Box::new(PostObjectInput {
                bucket: self.bucket,
                key: self.key,
                body: stream,
                content_type: self.content_type,
                metadata: self.metadata,
                fields: self.object_fields,
            })),
            Some(monitor),
        ))
    }
}

/// Legacy RustFS's sentence for an empty form file: the legacy stack's text for
/// `UnexpectedContent`.
const LEGACY_EMPTY_FILE: &str = "This request does not support content.";

#[derive(Debug)]
struct PostBodyError(&'static str, Option<Box<S3Error>>);

impl PostBodyError {
    fn into_refusal(self) -> S3Error {
        self.1.map_or_else(crate::gate::incomplete, |refusal| *refusal)
    }
}

impl fmt::Display for PostBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PostBodyError {}

struct PostFileBody<B: Body> {
    frames: WireFrames<B>,
    first: Option<Bytes>,
    initial: bool,
    /// The RustFS profile: a policy refusal in legacy RustFS's words, and an empty file refused.
    legacy_policy_errors: bool,
    file: FileReader,
    policy: AcceptedPolicy,
    bucket: String,
    key: String,
    ended: bool,
    // The parser may emit a copied boundary carry followed by a borrowed input run. Keep them
    // separate and in order, and drain them before polling the transport again.
    pending: VecDeque<Bytes>,
}

/// Legacy RustFS's answer to an empty form file: `400 UnexpectedContent`.
fn legacy_empty_file_refusal() -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::UNEXPECTED_CONTENT, LEGACY_EMPTY_FILE),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

/// Legacy RustFS's answer to a file its POST policy refuses: the policy's own code where it has
/// one, `AccessDenied` otherwise.
fn legacy_file_policy_refusal(error: PostPolicyError) -> S3Error {
    let code = match error {
        PostPolicyError::ConditionFailed => ErrorCode::INVALID_POLICY_DOCUMENT,
        PostPolicyError::EntityTooSmall => ErrorCode::ENTITY_TOO_SMALL,
        PostPolicyError::EntityTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        _ => ErrorCode::ACCESS_DENIED,
    };
    from_handler(
        HandlerError::new(code, "the POST file did not satisfy its policy"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

/// Retains input subslices without copying; only the parser's bounded carry needs new ownership.
fn retain_file_bytes(frame: &Bytes, bytes: &[u8]) -> Bytes {
    let start = (bytes.as_ptr() as usize).wrapping_sub(frame.as_ptr() as usize);
    if start <= frame.len() && bytes.len() <= frame.len() - start {
        frame.slice(start..start + bytes.len())
    } else {
        Bytes::copy_from_slice(bytes)
    }
}

impl<B: Body> PostFileBody<B> {
    fn policy_error(&self, message: &'static str, error: PostPolicyError) -> PostBodyError {
        let refusal = self.legacy_policy_errors.then(|| {
            let refusal = legacy_file_policy_refusal(error);
            Box::new(self.frames.mark_refusal_if_unfinished(refusal))
        });
        PostBodyError(message, refusal)
    }

    /// Ends the file once the form is known to be complete: the policy's final checks, then what
    /// is still pending, then the end of the body.
    fn complete(&mut self, file_bytes: u64) -> Poll<Option<Result<Frame<Bytes>, PostBodyError>>> {
        if let Err(error) = self.policy.enforce_final(&self.bucket, &self.key, file_bytes) {
            self.pending.clear();
            return Poll::Ready(Some(Err(self.policy_error("the POST file did not satisfy its policy", error))));
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS hands its upload path no length for an
        // empty file, and that path refuses `400 UnexpectedContent` before storing anything
        // (`rustfs/src/app/object/put.rs:91-116` at rustfs/rustfs@95268a3b9), after the policy's
        // own checks. An empty upload is a valid object everywhere else; the intended future
        // behaviour is to store it, as `PutObject` does (rustfs/gateway#1167).
        if self.legacy_policy_errors && file_bytes == 0 {
            self.pending.clear();
            let refusal = Box::new(self.frames.mark_refusal_if_unfinished(legacy_empty_file_refusal()));
            return Poll::Ready(Some(Err(PostBodyError("the POST file was empty", Some(refusal)))));
        }
        Poll::Ready(self.pending.pop_front().map(|bytes| Ok(Frame::data(bytes))))
    }
}

impl<B> Body for PostFileBody<B>
where
    B: Body,
{
    type Data = Bytes;
    type Error = PostBodyError;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if self.ended {
            return Poll::Ready(None);
        }
        loop {
            let frame = if self.initial {
                self.initial = false;
                Bytes::new()
            } else {
                match self.first.take() {
                    Some(frame) => frame,
                    None => match self.frames.poll_next(context) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(_)) => {
                            return Poll::Ready(Some(Err(PostBodyError("the POST body transport failed", None))));
                        }
                        Poll::Ready(Ok(None)) => {
                            // The legacy RustFS grammar confirms its close only at the end of the
                            // body; the gateway grammar never gets here with a complete form.
                            self.ended = true;
                            return match self.file.finish() {
                                Ok(file_bytes) => self.complete(file_bytes),
                                Err(_) => {
                                    Poll::Ready(Some(Err(PostBodyError("the POST form ended before its closing boundary", None))))
                                }
                            };
                        }
                        Poll::Ready(Ok(Some(frame))) => frame,
                    },
                }
            };
            let step = {
                let this = &mut *self;
                let mut sink = |bytes: &[u8]| {
                    if !bytes.is_empty() {
                        this.pending.push_back(retain_file_bytes(&frame, bytes));
                    }
                };
                this.file.push(&frame, &mut sink)
            };
            match step {
                Ok(FileStep::NeedMore) => {
                    if let Some(bytes) = self.pending.pop_front() {
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                }
                Ok(FileStep::Complete { file_bytes }) => {
                    self.ended = true;
                    return self.complete(file_bytes);
                }
                Err(FormReject::FileTooLarge) => {
                    self.pending.clear();
                    self.ended = true;
                    return Poll::Ready(Some(Err(
                        self.policy_error("the POST file exceeded its policy ceiling", PostPolicyError::EntityTooLarge)
                    )));
                }
                Err(_) => {
                    self.pending.clear();
                    self.ended = true;
                    return Poll::Ready(Some(Err(PostBodyError("the POST form was malformed", None))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended && self.pending.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn form_refusal(reject: FormReject) -> S3Error {
    let code = match reject {
        FormReject::FileTooLarge | FormReject::WholeStreamTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        FormReject::IncompleteStream => ErrorCode::INCOMPLETE_BODY,
        _ => ErrorCode::MALFORMED_POST_REQUEST,
    };
    from_handler(
        HandlerError::new(code, "the POST form was not accepted"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

fn policy_refusal(reject: PostPolicyError) -> S3Error {
    let code = match reject {
        PostPolicyError::EntityTooLarge => ErrorCode::ENTITY_TOO_LARGE,
        PostPolicyError::EntityTooSmall => ErrorCode::ENTITY_TOO_SMALL,
        PostPolicyError::Malformed => ErrorCode::MALFORMED_POST_REQUEST,
        PostPolicyError::Expired | PostPolicyError::ConditionFailed | PostPolicyError::SignatureMismatch => {
            ErrorCode::ACCESS_DENIED
        }
        _ => ErrorCode::ACCESS_DENIED,
    };
    from_handler(
        HandlerError::new(code, "the POST policy was not accepted"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    )
}

#[path = "post_object/legacy.rs"]
mod legacy;

#[cfg(test)]
#[path = "post_object/tests.rs"]
mod streaming_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    const BOUNDARY: &str = "----RustFSPostUnit";

    fn form(file: &str) -> Bytes {
        Bytes::from(format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n\
             --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\n\
             {file}\r\n--{BOUNDARY}--\r\n"
        ))
    }

    fn truncated_form(file: &str) -> Bytes {
        Bytes::from(format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n\
             --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\n\
             {file}"
        ))
    }

    async fn resolved(body: Bytes, limits: FormLimits) -> Result<ResolvedPostObject<Full<Bytes>>, String> {
        let prelude = PostObjectPrelude::read(
            Some(Full::new(body)),
            &format!("multipart/form-data; boundary={BOUNDARY}"),
            limits,
            BodyTimeouts::S3,
        )
        .await
        .map_err(|_| "fixture form prelude must parse".to_owned())?;
        let bucket = BucketName::new("example-bucket").map_err(|_| "fixture bucket must be valid".to_owned())?;
        prelude
            .resolve(bucket, &NamePolicy::default(), RequestNow::from_unix_seconds(0))
            .map_err(|_| "fixture anonymous form must resolve".to_owned())
    }

    fn file_body(resolved: ResolvedPostObject<Full<Bytes>>) -> PostFileBody<Full<Bytes>> {
        PostFileBody {
            frames: resolved.frames,
            first: resolved.first_file_bytes,
            initial: true,
            legacy_policy_errors: resolved.legacy_policy_errors,
            file: resolved.file,
            policy: resolved.policy,
            bucket: resolved.bucket.as_str().to_owned(),
            key: resolved.key.as_str().to_owned(),
            ended: false,
            pending: VecDeque::new(),
        }
    }

    #[tokio::test]
    async fn an_anonymous_file_adapter_reaches_its_closing_boundary() -> Result<(), String> {
        let bytes = file_body(resolved(form("hello"), FormLimits::default()).await?)
            .collect()
            .await
            .map_err(|error| error.to_string())?
            .to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn an_anonymous_file_stops_at_the_deployment_ceiling() -> Result<(), String> {
        let result = file_body(resolved(form("hello"), FormLimits::default().with_max_file_bytes(4)).await?)
            .collect()
            .await;
        assert!(result.is_err(), "five bytes exceed the four-byte ceiling");
        let Err(error) = result else {
            return Ok(());
        };
        assert_eq!(error.to_string(), "the POST file exceeded its policy ceiling");
        Ok(())
    }

    #[test]
    fn an_anonymous_form_names_the_deployment_ceiling_before_file_reading() {
        let limits = FormLimits::default().with_max_file_bytes(4);
        assert_eq!(AcceptedPolicy::Anonymous.read_ceiling(limits), 4);
    }

    #[tokio::test]
    async fn a_truncated_file_never_becomes_a_successful_eof() -> Result<(), String> {
        let result = file_body(resolved(truncated_form("hello"), FormLimits::default()).await?)
            .collect()
            .await;
        assert!(result.is_err(), "the closing boundary is required");
        let Err(error) = result else {
            return Ok(());
        };
        assert_eq!(error.to_string(), "the POST form ended before its closing boundary");
        Ok(())
    }
}
