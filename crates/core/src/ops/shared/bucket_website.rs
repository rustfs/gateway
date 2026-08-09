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

//! The static-website document: what a stored one is allowed to say.
//!
//! Shares: bucket_website
//! Members: DeleteBucketWebsite, GetBucketWebsite, PutBucketWebsite
//!
//! Responsible for: the semantic rules of a `WebsiteConfiguration` document — the exclusion
//! between a whole-site redirect and a document-serving site, the floor on a routing rule's
//! condition, and the closed `<Protocol>` set — held once so that every backend refuses the same
//! documents with the same codes.
//! NOT responsible for: decoding the document (the generated codec, which already refuses a
//! `<RoutingRule>` with no `<Redirect>` because the model makes that member required), storing
//! it, or **serving** anything from it. Resolving a request against the index document, mapping a
//! status to the error document, answering a routing rule with a 301 or 302, and the
//! `x-amz-website-redirect-location` header are the website endpoint's — a second protocol face
//! beside the REST API, out of this family's scope and out of this file's.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Why the exclusion is a refusal and the rest is not
//!
//! `<RedirectAllRequestsTo>` says "this bucket is one redirect". `<IndexDocument>` and its
//! neighbours say "this bucket is a site". A document carrying both describes two sites, and there
//! is no reading of it that serves anything predictable — AWS documents the members as mutually
//! exclusive, so the write refuses it rather than picking one.
//!
//! Everything else passes on purpose, for the reason [`super::bucket_config`] states at length:
//! a stored configuration is re-parsed by every future release and RustFS's persistence fails
//! open, so a decoder that got stricter would silently un-configure sites this release accepted.
//! A rule whose `<Condition>` matches nothing in particular, a `<HttpRedirectCode>` that is not a
//! number, an `<ErrorDocument>` naming a key that does not exist — all stored as sent, because
//! AWS documents no refusal for them and the runtime half is where they would matter.
//!
//! # The refusal messages are constant
//!
//! No reason below is built from request bytes. A website document carries host names and key
//! prefixes chosen by the caller; echoing one into an error body would put caller-controlled text
//! into every log line that captures the refusal.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::WebsiteConfiguration;

/// The two values a `<Protocol>` may carry, in either a whole-site redirect or a routing rule.
const PROTOCOLS: &[&str] = &["http", "https"];

/// Why a decoded website document was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebsiteRejection {
    /// `<RedirectAllRequestsTo>` beside any of `<IndexDocument>`, `<ErrorDocument>` or
    /// `<RoutingRules>`: two incompatible descriptions of one site.
    RedirectAllWithDocuments,
    /// A document with neither a whole-site redirect nor an `<IndexDocument>`. A site with no
    /// entry point cannot answer a request for `/`, and the model makes neither member required,
    /// so the empty document reaches here rather than the decoder.
    NoEntryPoint,
    /// A `<Protocol>` outside `http`/`https`.
    ProtocolUnknown,
    /// A `<RedirectAllRequestsTo>` with an empty `<HostName>`. The member is required by the
    /// model, so the empty string is the one value the decoder lets through.
    RedirectHostEmpty,
    /// A `<RoutingRule>` whose `<Redirect>` replaces both the key and the key prefix. The two are
    /// alternative rewrites of the same request and AWS documents them as exclusive.
    RedirectReplacesKeyTwice,
}

impl WebsiteRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // Every one of these is "the document is not the document": a structural rule about
            // which elements may appear together, which is what MalformedXML names.
            WebsiteRejection::RedirectAllWithDocuments
            | WebsiteRejection::NoEntryPoint
            | WebsiteRejection::RedirectReplacesKeyTwice => ErrorCode::MALFORMED_XML,
            // A present, well-formed value this operation cannot use.
            WebsiteRejection::ProtocolUnknown | WebsiteRejection::RedirectHostEmpty => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            WebsiteRejection::RedirectAllWithDocuments => {
                "RedirectAllRequestsTo cannot be combined with IndexDocument, ErrorDocument or RoutingRules"
            }
            WebsiteRejection::NoEntryPoint => "the configuration must carry either RedirectAllRequestsTo or IndexDocument",
            WebsiteRejection::ProtocolUnknown => "Protocol must be either http or https",
            WebsiteRejection::RedirectHostEmpty => "RedirectAllRequestsTo requires a HostName",
            WebsiteRejection::RedirectReplacesKeyTwice => {
                "a Redirect carries either ReplaceKeyWith or ReplaceKeyPrefixWith, never both"
            }
        }
    }
}

/// Checks a decoded website document against the family's semantic rules, first refusal wins.
///
/// Members are checked in the order the wire carries them and rules in document order, so the same
/// document is refused for the same reason on every backend.
///
/// # Errors
///
/// [`WebsiteRejection`] naming the first rule the document breaks.
pub fn validate_website(configuration: &WebsiteConfiguration) -> Result<(), WebsiteRejection> {
    let documents = configuration.index_document.is_some()
        || configuration.error_document.is_some()
        || !configuration.routing_rules.is_empty();
    match configuration.redirect_all_requests_to.as_ref() {
        Some(redirect) => {
            if documents {
                return Err(WebsiteRejection::RedirectAllWithDocuments);
            }
            if redirect.host_name.is_empty() {
                return Err(WebsiteRejection::RedirectHostEmpty);
            }
            if let Some(protocol) = redirect.protocol.as_ref()
                && !PROTOCOLS.contains(&protocol.as_str())
            {
                return Err(WebsiteRejection::ProtocolUnknown);
            }
        }
        None if configuration.index_document.is_none() => return Err(WebsiteRejection::NoEntryPoint),
        None => {}
    }
    for rule in &configuration.routing_rules {
        if rule.redirect.replace_key_with.is_some() && rule.redirect.replace_key_prefix_with.is_some() {
            return Err(WebsiteRejection::RedirectReplacesKeyTwice);
        }
        if let Some(protocol) = rule.redirect.protocol.as_ref()
            && !PROTOCOLS.contains(&protocol.as_str())
        {
            return Err(WebsiteRejection::ProtocolUnknown);
        }
    }
    Ok(())
}
