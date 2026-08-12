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

//! The access control list: which of its two wire channels a request used, and what each one is
//! allowed to say.
//!
//! Shares: acl
//! Members: GetBucketAcl, PutBucketAcl, GetObjectAcl, PutObjectAcl
//!
//! Responsible for: the mutual exclusion of the two channels an ACL write may arrive on — the
//! `<AccessControlPolicy>` body and the `x-amz-acl` / `x-amz-grant-*` headers — the closed
//! canned-ACL sets and which of them a bucket and an object each accept, the one parser for the
//! grant-header grammar, the closed `Permission` set, and the derivation of the `<Grantee>`
//! discriminator this project's XML reader cannot see.
//! NOT responsible for: **evaluating** an ACL. Whether a grant lets a principal read an object is
//! the deployment's `Authorizer`'s question and no function here answers it; nothing here reads a
//! request identity, and the canned ACLs are validated rather than expanded into grants, because
//! expansion needs the bucket owner and the object owner — state this layer does not have.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Two channels, one grammar, one parser
//!
//! An ACL write can say the same thing twice over: as an XML document in the body, or as a canned
//! ACL and a set of grant headers. That is the family's whole difficulty, and the reason the
//! grammar is parsed in exactly one place. Two parsers for one grammar drift — one accepts a
//! trailing comma the other refuses, one lower-cases the key and the other does not — and the two
//! channels then disagree about what the client asked for while both answer `200`.
//!
//! # Why the `xsi:type` discriminator is derived rather than read
//!
//! AWS discriminates `<Grantee>` with an XML **attribute**: `xsi:type="CanonicalUser"`, `"Group"`
//! or `"AmazonCustomerByEmail"`. The frozen IR reserves `xml.attributes` for exactly this and the
//! generated encoder writes it, so a read answers the bytes `aws-java-sdk` expects. The **read**
//! side cannot: `rustfs_gateway_xml::XmlNode` carries an element's name, text and children and no
//! attributes at all, and widening that type is outside this task's fence. So a decoded grantee
//! arrives with its discriminator unset, and [`resolve_grantee_type`] derives it from the
//! identifying member the grantee does carry — `<ID>`, `<URI>` or `<EmailAddress>` — refusing a
//! grantee that carries none or more than one. For every document AWS itself would accept the
//! derivation and the attribute agree, because the attribute names the member that is present;
//! the divergence is a document whose attribute contradicts its members, which this decoder reads
//! by the members. That is `q-acl-0004`, and it is recorded as a quirk rather than hidden because
//! it is a real difference from AWS, not an implementation detail.
//!
//! # The refusal reasons never repeat a grantee
//!
//! A canonical user id and an email address are both identities, and a refusal that echoed one
//! would copy it into an error body and into every log line that captures one. Every reason below
//! is a constant, and none of them is built from request bytes — the same stance
//! [`super::cors`] and [`super::replication`] take, for the same reason.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{AccessControlPolicy, Grant, Grantee, Permission, Type};

use crate::contracts::{
    ACL_BUCKET_CANNED_VALUES, ACL_CHANNEL_POLICY, ACL_ERROR_SECRET_FLOW_POLICY, ACL_GRANT_HEADER_KEYS,
    ACL_GRANT_HEADER_MAX_BYTES, ACL_GRANT_HEADER_MAX_ENTRIES, ACL_GRANT_KEYS_CASE_INSENSITIVE, ACL_GRANTEE_DISCRIMINATOR_POLICY,
    ACL_OBJECT_CANNED_VALUES, ACL_OWNER_POLICY, ACL_PERMISSION_VALUES, AclChannelPolicy, AclErrorSecretFlowPolicy,
    AclOwnerPolicy, GranteeDiscriminatorPolicy,
};

/// The XML Schema instance namespace `<Grantee>` declares so that `xsi:type` resolves.
///
/// AWS writes the declaration on the `<Grantee>` element itself rather than on the document root,
/// and a strict client that resolves prefixes refuses the attribute without it.
pub const XSI_NAMESPACE: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// The predefined group that means "anyone, authenticated or not".
pub const ALL_USERS_GROUP: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

/// The predefined group that means "any AWS account".
pub const AUTHENTICATED_USERS_GROUP: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

/// The predefined group server access logging delivers through.
pub const LOG_DELIVERY_GROUP: &str = "http://acs.amazonaws.com/groups/s3/LogDelivery";

/// The longest an `x-amz-grant-*` header may be, in bytes.
///
/// A grant header is a short list of identities; eight kilobytes is already an order of magnitude
/// past the longest legitimate one. The ceiling exists so that a header of thousands of grantees
/// is refused at a bound rather than parsed into a vector whose size the sender chose.
pub const MAX_GRANT_HEADER_BYTES: usize = ACL_GRANT_HEADER_MAX_BYTES;

/// The most grantees one `x-amz-grant-*` header may name.
///
/// AWS caps an ACL at 100 grants in total, so a single header naming more than that cannot
/// describe an ACL any implementation would store.
pub const MAX_GRANTEES_PER_HEADER: usize = ACL_GRANT_HEADER_MAX_ENTRIES;

/// Whether an ACL is being read or written on a bucket or on an object.
///
/// The two accept different canned ACLs, and the difference is not cosmetic:
/// `bucket-owner-full-control` on a bucket and `log-delivery-write` on an object are both
/// meaningless, and accepting one would store a grant nothing can ever evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclTarget {
    /// The ACL of a bucket.
    Bucket,
    /// The ACL of one object version.
    Object,
}

/// The canned ACLs a **bucket** accepts, in AWS's own documented order.
pub const BUCKET_CANNED_ACLS: &[&str] = ACL_BUCKET_CANNED_VALUES;

/// The canned ACLs an **object** accepts, in AWS's own documented order.
pub const OBJECT_CANNED_ACLS: &[&str] = ACL_OBJECT_CANNED_VALUES;

/// Every permission a `<Grant>` may name. The set is closed, and AWS refuses anything else.
pub const PERMISSIONS: &[&str] = ACL_PERMISSION_VALUES;

impl AclTarget {
    /// The canned ACLs this target accepts.
    #[must_use]
    pub const fn canned_acls(self) -> &'static [&'static str] {
        match self {
            AclTarget::Bucket => BUCKET_CANNED_ACLS,
            AclTarget::Object => OBJECT_CANNED_ACLS,
        }
    }
}

/// Which kind of identity a `<Grantee>` names — the value of its `xsi:type` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GranteeType {
    /// A canonical user id, in `<ID>`.
    CanonicalUser,
    /// An account's registered email address, in `<EmailAddress>`.
    AmazonCustomerByEmail,
    /// One of the predefined groups, in `<URI>`.
    Group,
}

impl GranteeType {
    /// The wire spelling of the `xsi:type` attribute.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GranteeType::CanonicalUser => "CanonicalUser",
            GranteeType::AmazonCustomerByEmail => "AmazonCustomerByEmail",
            GranteeType::Group => "Group",
        }
    }

    /// The dto value the encoder writes into the attribute.
    #[must_use]
    pub fn as_dto(self) -> Type {
        match self {
            GranteeType::CanonicalUser => Type::CANONICALUSER,
            GranteeType::AmazonCustomerByEmail => Type::AMAZONCUSTOMERBYEMAIL,
            GranteeType::Group => Type::GROUP,
        }
    }

    /// The grant-header key that names this kind of identity, lower-cased.
    #[must_use]
    pub const fn header_key(self) -> &'static str {
        match self {
            GranteeType::CanonicalUser => "id",
            GranteeType::AmazonCustomerByEmail => "emailaddress",
            GranteeType::Group => "uri",
        }
    }
}

/// Why an ACL request was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`AclRejection::code`] and [`AclRejection::reason`] are the two
/// halves an S3 error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclRejection {
    /// An `<AccessControlPolicy>` body and an ACL header in the same request: two channels saying
    /// the same thing, and no rule that says which one wins.
    BothChannels,
    /// Neither channel: an ACL write that names no access control at all.
    NoChannel,
    /// `x-amz-acl` naming a value that is not a canned ACL at all.
    CannedUnknown,
    /// `x-amz-acl` naming a canned ACL that exists but not for this target.
    CannedWrongTarget,
    /// An `x-amz-grant-*` header that is not a comma-separated list of quoted `key="value"` pairs.
    GrantSyntax,
    /// Mutation-only form that carries the rejected grant header into the reason.
    GrantSyntaxWithValue(String),
    /// An `x-amz-grant-*` header whose pair names a key that is not `id`, `uri` or `emailAddress`.
    GrantUnknownKey,
    /// Mutation-only form that carries the rejected grant header into the reason.
    GrantUnknownKeyWithValue(String),
    /// An `x-amz-grant-*` header past [`MAX_GRANT_HEADER_BYTES`] or [`MAX_GRANTEES_PER_HEADER`].
    GrantTooLarge,
    /// Mutation-only form that carries the rejected grant header into the reason.
    GrantTooLargeWithValue(String),
    /// A `<Grantee>` carrying no identifying member, so its `xsi:type` cannot be derived.
    GranteeUnidentified,
    /// A `<Grantee>` carrying more than one identifying member, so its `xsi:type` is ambiguous.
    GranteeAmbiguous,
    /// A `<Grant>` with no `<Grantee>` at all.
    GrantWithoutGrantee,
    /// A `<Permission>` outside [`PERMISSIONS`], or a `<Grant>` with none.
    PermissionUnknown,
}

impl AclRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // Two well-formed channels whose combination the operation refuses. AWS answers the
            // generic request-level code here, not a document-level one: neither channel is
            // malformed, the pair is.
            AclRejection::BothChannels => ErrorCode::INVALID_REQUEST,
            // A value outside a closed set, or a header whose grammar does not parse: a
            // parameter fault, which is what InvalidArgument is for.
            AclRejection::CannedUnknown
            | AclRejection::CannedWrongTarget
            | AclRejection::GrantSyntax
            | AclRejection::GrantSyntaxWithValue(_)
            | AclRejection::GrantUnknownKey
            | AclRejection::GrantUnknownKeyWithValue(_)
            | AclRejection::GrantTooLarge
            | AclRejection::GrantTooLargeWithValue(_) => ErrorCode::INVALID_ARGUMENT,
            // The document does not say what it has to say: absent, or structurally
            // contradictory. A write with neither channel is the empty-document case.
            AclRejection::NoChannel
            | AclRejection::GranteeUnidentified
            | AclRejection::GranteeAmbiguous
            | AclRejection::GrantWithoutGrantee
            | AclRejection::PermissionUnknown => ErrorCode::MALFORMED_XML,
        }
    }

    /// A constant explanation, never built from request bytes — and in particular never carrying
    /// the canonical user id, the email address or the group URI the request named
    /// (`q-acl-0010`).
    #[must_use]
    pub fn reason(&self) -> &str {
        match ACL_ERROR_SECRET_FLOW_POLICY {
            AclErrorSecretFlowPolicy::ConstantReasons => self.constant_reason(),
            AclErrorSecretFlowPolicy::EchoRejectedValue => match self {
                AclRejection::GrantSyntaxWithValue(value)
                | AclRejection::GrantUnknownKeyWithValue(value)
                | AclRejection::GrantTooLargeWithValue(value) => value,
                _ => self.constant_reason(),
            },
        }
    }

    const fn constant_reason(&self) -> &'static str {
        match self {
            AclRejection::BothChannels => {
                "Specifying both an AccessControlPolicy body and an ACL header in the same request is not allowed"
            }
            AclRejection::NoChannel => {
                "An ACL write must carry either an AccessControlPolicy body or an ACL header, and this one carries neither"
            }
            AclRejection::CannedUnknown => "The x-amz-acl header does not name a canned ACL",
            AclRejection::CannedWrongTarget => "This canned ACL is not one this resource accepts",
            AclRejection::GrantSyntax => {
                "A grant header is a comma-separated list of quoted pairs, as id=\"...\", uri=\"...\" or emailAddress=\"...\""
            }
            AclRejection::GrantSyntaxWithValue(_) => "The rejected grant header is included in the mutation response",
            AclRejection::GrantUnknownKey => "A grant header pair must name id, uri or emailAddress",
            AclRejection::GrantUnknownKeyWithValue(_) => "The rejected grant header is included in the mutation response",
            AclRejection::GrantTooLarge => "The grant header is longer, or names more grantees, than this request may carry",
            AclRejection::GrantTooLargeWithValue(_) => "The rejected grant header is included in the mutation response",
            AclRejection::GranteeUnidentified => {
                "A Grantee must carry exactly one of ID, URI or EmailAddress, and this one carries none"
            }
            AclRejection::GranteeAmbiguous => {
                "A Grantee must carry exactly one of ID, URI or EmailAddress, and this one carries more than one"
            }
            AclRejection::GrantWithoutGrantee => "A Grant must specify a Grantee",
            AclRejection::PermissionUnknown => {
                "A Grant must specify one of the permissions FULL_CONTROL, WRITE, WRITE_ACP, READ or READ_ACP"
            }
        }
    }

    fn grant_syntax(value: &str) -> Self {
        match ACL_ERROR_SECRET_FLOW_POLICY {
            AclErrorSecretFlowPolicy::ConstantReasons => AclRejection::GrantSyntax,
            AclErrorSecretFlowPolicy::EchoRejectedValue => AclRejection::GrantSyntaxWithValue(value.to_owned()),
        }
    }

    fn grant_unknown_key(value: &str) -> Self {
        match ACL_ERROR_SECRET_FLOW_POLICY {
            AclErrorSecretFlowPolicy::ConstantReasons => AclRejection::GrantUnknownKey,
            AclErrorSecretFlowPolicy::EchoRejectedValue => AclRejection::GrantUnknownKeyWithValue(value.to_owned()),
        }
    }

    fn grant_too_large(value: &str) -> Self {
        match ACL_ERROR_SECRET_FLOW_POLICY {
            AclErrorSecretFlowPolicy::ConstantReasons => AclRejection::GrantTooLarge,
            AclErrorSecretFlowPolicy::EchoRejectedValue => AclRejection::GrantTooLargeWithValue(value.to_owned()),
        }
    }
}

/// The ACL headers of one request, already lifted off the wire by the generated decoder.
///
/// A borrowed view rather than the header map, so this contract stays a function of values and
/// the layer below keeps its own vocabulary. Every member is the raw header value; nothing here
/// has been validated yet.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AclHeaders<'a> {
    /// `x-amz-acl`.
    pub canned: Option<&'a str>,
    /// `x-amz-grant-full-control`.
    pub full_control: Option<&'a str>,
    /// `x-amz-grant-read`.
    pub read: Option<&'a str>,
    /// `x-amz-grant-write`.
    pub write: Option<&'a str>,
    /// `x-amz-grant-read-acp`.
    pub read_acp: Option<&'a str>,
    /// `x-amz-grant-write-acp`.
    pub write_acp: Option<&'a str>,
}

impl AclHeaders<'_> {
    /// Whether the request used the header channel at all.
    ///
    /// A present-but-empty `x-amz-acl` counts as used: the client meant to name a canned ACL and
    /// named nothing, which is a refusal rather than a request that did not use the channel.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.canned.is_some() || self.grants_present()
    }

    /// Whether any explicit grant header is present.
    #[must_use]
    pub const fn grants_present(&self) -> bool {
        self.full_control.is_some()
            || self.read.is_some()
            || self.write.is_some()
            || self.read_acp.is_some()
            || self.write_acp.is_some()
    }

    /// The five grant headers paired with the permission each one grants, in a fixed order.
    #[must_use]
    fn grant_headers(&self) -> [(&'static str, Option<&str>); 5] {
        [
            ("FULL_CONTROL", self.full_control),
            ("WRITE", self.write),
            ("WRITE_ACP", self.write_acp),
            ("READ", self.read),
            ("READ_ACP", self.read_acp),
        ]
    }
}

/// Which channel an ACL write used, resolved and validated.
///
/// No `PartialEq`: the generated dto structures it carries have none, and deriving one here would
/// need it on every shape in the ACL tree for the benefit of test assertions alone.
#[derive(Debug, Clone)]
pub enum AclInput {
    /// The `<AccessControlPolicy>` body, canonicalised: every grantee carries the `xsi:type` a
    /// read will write back.
    Document(AccessControlPolicy),
    /// The header channel: an optional canned ACL and the grants the explicit headers named.
    Headers {
        /// `x-amz-acl`, validated against the target's set. `None` when only grant headers were
        /// sent.
        canned: Option<&'static str>,
        /// One entry per grantee named by an explicit grant header, in permission order.
        grants: Vec<Grant>,
    },
}

/// Decides which channel an ACL write used, and refuses the two combinations that have no answer.
///
/// The body and the headers are mutually exclusive, and a write must use one of them. Within the
/// header channel a canned ACL and explicit grants may coexist: AWS documents the body/header
/// exclusion and documents no exclusion between the two header spellings, so refusing that
/// combination would be a rule of this project's own invention (`q-acl-0007`).
///
/// # Errors
///
/// [`AclRejection`] naming the first rule the request breaks.
pub fn resolve_input(
    headers: AclHeaders<'_>,
    body: Option<AccessControlPolicy>,
    target: AclTarget,
) -> Result<AclInput, AclRejection> {
    if matches!(ACL_CHANNEL_POLICY, AclChannelPolicy::RejectMixedHeaders) && headers.canned.is_some() && headers.grants_present()
    {
        return Err(AclRejection::BothChannels);
    }
    match (headers.present(), body) {
        (true, Some(_)) => Err(AclRejection::BothChannels),
        (false, None) => Err(AclRejection::NoChannel),
        (false, Some(mut document)) => {
            canonicalize_policy(&mut document)?;
            Ok(AclInput::Document(document))
        }
        (true, None) => {
            let canned = match headers.canned {
                Some(value) => Some(parse_canned(value, target)?),
                None => None,
            };
            let mut grants = Vec::new();
            for (permission, raw) in headers.grant_headers() {
                let Some(raw) = raw else { continue };
                for grantee in parse_grant_header(raw)? {
                    grants.push(Grant {
                        grantee: Some(grantee),
                        permission: Some(Permission::custom(permission.to_owned())),
                    });
                }
            }
            Ok(AclInput::Headers { canned, grants })
        }
    }
}

/// Validates one `x-amz-acl` value against the set its target accepts.
///
/// The returned string is the canonical spelling from the target's own set, never the caller's
/// bytes, so nothing downstream can echo an unvalidated value back.
///
/// # Errors
///
/// [`AclRejection::CannedUnknown`] for a value no target accepts — an empty one included, which
/// is how a header sent with no value is refused rather than read as `private` — and
/// [`AclRejection::CannedWrongTarget`] for one the *other* target accepts.
pub fn parse_canned(value: &str, target: AclTarget) -> Result<&'static str, AclRejection> {
    if let Some(found) = target.canned_acls().iter().find(|candidate| **candidate == value) {
        return Ok(found);
    }
    let other = match target {
        AclTarget::Bucket => OBJECT_CANNED_ACLS,
        AclTarget::Object => BUCKET_CANNED_ACLS,
    };
    if other.contains(&value) {
        return Err(AclRejection::CannedWrongTarget);
    }
    Err(AclRejection::CannedUnknown)
}

/// Parses one `x-amz-grant-*` header into the grantees it names.
///
/// The grammar is a comma-separated list of `key="value"` pairs. Surrounding whitespace is
/// tolerated and the key is matched case-insensitively, because the AWS SDKs do not agree on
/// either; the quotation marks are **not** optional, because without them the value's end is
/// undecidable and a comma inside a value would silently split one grantee into two. Values are
/// read between the quotes, so a comma inside one is a comma and not a separator.
///
/// # Errors
///
/// [`AclRejection::GrantSyntax`] for a pair that is not `key="value"` — an unquoted value, an
/// unterminated quote, an empty value or a trailing separator — [`AclRejection::GrantUnknownKey`]
/// for a key outside the three, and [`AclRejection::GrantTooLarge`] at either ceiling.
pub fn parse_grant_header(value: &str) -> Result<Vec<Grantee>, AclRejection> {
    if value.len() > MAX_GRANT_HEADER_BYTES {
        return Err(AclRejection::grant_too_large(value));
    }
    let mut out: Vec<Grantee> = Vec::new();
    let mut rest = value;
    loop {
        rest = rest.trim_start();
        let Some((key, after_key)) = rest.split_once('=') else {
            return Err(AclRejection::grant_syntax(value));
        };
        let key = if ACL_GRANT_KEYS_CASE_INSENSITIVE {
            key.trim_end().to_ascii_lowercase()
        } else {
            key.trim_end().to_owned()
        };
        // A key is letters and nothing else. Without this a leading separator — `,id="a"` —
        // parses as a key called `,id` and is refused for the wrong reason, and a key carrying
        // a stray quote or bracket would be reported as an unknown key rather than as the
        // grammar violation it is.
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(AclRejection::grant_syntax(value));
        }
        if !ACL_GRANT_HEADER_KEYS.contains(&key.as_str()) {
            return Err(AclRejection::grant_unknown_key(value));
        }
        // Whitespace either side of the `=` is tolerated for the same reason the key's case is:
        // it carries no meaning, and a client cannot fix a refusal for it by changing anything it
        // controls. The quote that follows is not optional.
        let Some(quoted) = after_key.trim_start().strip_prefix('"') else {
            return Err(AclRejection::grant_syntax(value));
        };
        let Some((literal, after_value)) = quoted.split_once('"') else {
            return Err(AclRejection::grant_syntax(value));
        };
        if literal.is_empty() {
            return Err(AclRejection::grant_syntax(value));
        }
        if out.len() >= MAX_GRANTEES_PER_HEADER {
            return Err(AclRejection::grant_too_large(value));
        }
        out.push(grantee_of(&key, literal)?);
        rest = after_value.trim_start();
        match rest.strip_prefix(',') {
            Some(more) => rest = more,
            None if rest.is_empty() => break,
            // Anything but a separator after a closing quote is the grammar broken in the one
            // place a lenient parser would not notice: `id="a" id="b"` is two pairs to a human
            // and one truncated list to a parser that stopped looking.
            None => return Err(AclRejection::grant_syntax(value)),
        }
    }
    Ok(out)
}

/// One grant-header pair, as the grantee it names.
fn grantee_of(key: &str, literal: &str) -> Result<Grantee, AclRejection> {
    let kind = match key {
        "id" => GranteeType::CanonicalUser,
        "uri" => GranteeType::Group,
        "emailaddress" => GranteeType::AmazonCustomerByEmail,
        _ => return Err(AclRejection::GrantUnknownKey),
    };
    let mut grantee = Grantee {
        r#type: Some(kind.as_dto()),
        ..Grantee::default()
    };
    match kind {
        GranteeType::CanonicalUser => grantee.id = Some(literal.to_owned()),
        GranteeType::Group => grantee.uri = Some(literal.to_owned()),
        GranteeType::AmazonCustomerByEmail => grantee.email_address = Some(literal.to_owned()),
    }
    Ok(grantee)
}

/// Derives the `xsi:type` of one decoded `<Grantee>` from the member that identifies it.
///
/// The attribute itself is unreadable — see the module docs — so the identifying member is the
/// discriminator. Exactly one of `<ID>`, `<URI>` and `<EmailAddress>` must be present and
/// non-empty: none leaves the grantee nameless, and two leave it ambiguous, and both are
/// documents no read could ever write back.
///
/// # Errors
///
/// [`AclRejection::GranteeUnidentified`] or [`AclRejection::GranteeAmbiguous`].
pub fn resolve_grantee_type(grantee: &Grantee) -> Result<GranteeType, AclRejection> {
    let named = |value: &Option<String>| value.as_deref().is_some_and(|text| !text.is_empty());
    let candidates = [
        (named(&grantee.id), GranteeType::CanonicalUser),
        (named(&grantee.uri), GranteeType::Group),
        (named(&grantee.email_address), GranteeType::AmazonCustomerByEmail),
    ];
    let mut found = None;
    for (present, kind) in candidates {
        if !present {
            continue;
        }
        if found.is_some() {
            return Err(AclRejection::GranteeAmbiguous);
        }
        found = Some(kind);
    }
    found.ok_or(AclRejection::GranteeUnidentified)
}

/// Fills in every grantee's `xsi:type` and refuses a grant the wire cannot describe.
///
/// Called once, on the way in, so that what a backend stores is what a read writes back byte for
/// byte: a grantee whose discriminator was never set would be written without the attribute, and
/// that is the document `aws-java-sdk` cannot parse (`q-acl-0003`).
///
/// # Errors
///
/// [`AclRejection`] naming the first grant the document breaks, in document order.
pub fn canonicalize_policy(policy: &mut AccessControlPolicy) -> Result<(), AclRejection> {
    if matches!(ACL_OWNER_POLICY, AclOwnerPolicy::Drop) {
        policy.owner = None;
    }
    for grant in &mut policy.grants {
        let Some(grantee) = grant.grantee.as_mut() else {
            return Err(AclRejection::GrantWithoutGrantee);
        };
        match ACL_GRANTEE_DISCRIMINATOR_POLICY {
            GranteeDiscriminatorPolicy::IdentifyingMember => {
                let kind = resolve_grantee_type(grantee)?;
                grantee.r#type = Some(kind.as_dto());
            }
            GranteeDiscriminatorPolicy::LeaveUnset => {}
        }
        match grant.permission.as_ref() {
            Some(permission) if PERMISSIONS.contains(&permission.as_str()) => {}
            _ => return Err(AclRejection::PermissionUnknown),
        }
    }
    Ok(())
}
