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

//! The one place a client-supplied name is normalised, and the floor no deployment can lower.
//!
//! Responsible for: the single decode, the [`SlashPolicy`] decision, the unconditional safety
//! floor for keys and bucket labels, and the [`NameValidator`] extension point whose answer can
//! only narrow what the floor already allowed.
//! NOT responsible for: percent-decoding the request target as a whole (`rustfs-gateway-http`
//! hands over one label at a time), canonicalising a request for signature purposes
//! (`rustfs-gateway-sig`, which reads the *raw* path and must never see a value from here),
//! authorisation, or mapping a key onto a physical path — that last one stays the deployment's
//! responsibility and is stated as such in `docs/security-model.md`.
//! Upstream: [`super::parse_error`]. Downstream: [`super::name`], and through it routing,
//! authorisation, auditing and storage, all of which read the same value.
//!
//! # Why "exactly once, in exactly one place" is the whole point
//!
//! Three published advisories against RustFS have the same shape: the value the authorisation
//! check read was not the value the storage layer used, because one of the two decoded,
//! normalised or cleaned something the other did not. The difference between the two values is
//! the vulnerability. So there is one function that turns a wire label into a name, every
//! consumer downstream reads its output, and no consumer is given a spelling it could re-parse.
//!
//! # The order, and why each position is load-bearing
//!
//! ```text
//!   decode once        %2e%2e becomes .., %252e%252e becomes %2e%2e and is not decoded again
//!   refuse the residue an encoded separator that survived one decode is refused outright
//!   apply SlashPolicy  runs of `/` are preserved (AWS), folded (MinIO compatibility), or folded
//!                      only in a key that starts with `/` (legacy RustFS)
//!   floor              traversal, NUL, controls, absolute and UNC shapes, length, emptiness
//!   validator          may refuse more; has no way to permit anything the floor refused
//! ```
//!
//! The floor runs **before** the validator and its verdict is AND-ed with the validator's, so a
//! deployment that installs a permissive validator widens the bucket naming rules and nothing
//! else. That is why [`Stricter`] has no `Allow` variant: the type says what the pipeline does.

use std::sync::Arc;

use percent_encoding::percent_decode_str;
use unicode_normalization::UnicodeNormalization as _;

use super::error_code::ErrorCode;

/// Bucket name length bounds, in bytes.
pub(crate) const MIN_BUCKET_BYTES: usize = 3;
pub(crate) const MAX_BUCKET_BYTES: usize = 63;

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum ContractSlashPolicy {
    AwsPreserve,
    Collapse,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum PercentDecodePassesPolicy {
    Once,
    UntilStable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum DecodedUtf8Policy {
    Strict,
    Lossy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum ResidualEncodedDangerPolicy {
    Reject,
    Allow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum TraversalDelimitersPolicy {
    SlashAndBackslash,
    SlashOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum AbsoluteOrUncPolicy {
    Reject,
    Allow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum DefaultValidatorPolicy {
    Aws,
    Permissive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum ValidatorReplaceabilityPolicy {
    CustomMayWidenAwsLayer,
    IgnoreCustom,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum ValidatorAuthorityPolicy {
    NarrowOnlyAfterFloor,
    CustomMayBypassFloor,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum ClientIngressCodepointPolicy {
    NulC0AndDel,
    NulOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum StoredLegacyControlPolicy {
    AllowNonNulAndEscapeOnXmlList,
    RejectAllControls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum UnicodeNormalizationPolicy {
    None,
    Nfc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the naming contract mutation gate")]
enum CaseFoldingPolicy {
    None,
    Lowercase,
}

include!("../../../../generated/naming_contracts.rs");

/// What happens to a run of consecutive slashes in a key.
///
/// Two implementations of S3 disagree, and the disagreement is observable: on AWS
/// `PUT /bucket//key` stores an object whose key is `/key`, and on MinIO it stores one whose key
/// is `key`. Neither is wrong, and a gateway that picks silently makes `a//b` and `a/b` the same
/// object for half its users and two objects for the other half.
///
/// The default is [`SlashPolicy::AwsPreserve`], because the default has to be the semantics the
/// service being emulated has.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SlashPolicy {
    /// AWS semantics: an empty path segment is part of the key and is kept.
    #[default]
    AwsPreserve,
    /// MinIO compatibility: a run of slashes folds to one, and a leading slash is dropped.
    ///
    /// It is not a cleaner: it folds separators and removes nothing else, so a `..` segment
    /// survives it and is refused by the floor afterwards. It is not what RustFS runs either:
    /// RustFS leaves `a//b` as sent, which is [`SlashPolicy::RustfsLegacy`].
    Collapse,
    /// Legacy RustFS: a key that starts with `/` has every run of slashes folded to one, its
    /// leading slashes dropped and one trailing slash kept, and a key of slashes only becomes `/`;
    /// every other key is left exactly as sent.
    ///
    /// So `PUT /bucket//x` stores `x`, `PUT /bucket/dir//x` stores `dir//x`, and
    /// `PUT /bucket//` names the key `/`. The RustFS profile's rule (rustfs/gateway#1101): legacy
    /// RustFS turns slash normalisation on (`rustfs/src/server/http.rs:166-172` on rustfs/rustfs
    /// `e870a6d25b`), and its path parser applies it to a key only when the key starts with `/`.
    ///
    /// Like [`SlashPolicy::Collapse`] it removes separators and nothing else, and the floor runs on
    /// the folded key: a `..` segment is still refused, and the length limit reads the folded key.
    RustfsLegacy,
}

impl SlashPolicy {
    /// Whether this policy can change the key an already-stored object would be found under.
    ///
    /// Read at start-up: switching the policy renames every object whose key held an empty
    /// segment, so it belongs in the security-posture report as a persistence-affecting setting
    /// rather than as a compatibility flag.
    #[must_use]
    pub fn rewrites_keys(self) -> bool {
        match self {
            Self::AwsPreserve => false,
            Self::Collapse | Self::RustfsLegacy => true,
        }
    }

    /// The identifier a posture report prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwsPreserve => "aws-preserve",
            Self::Collapse => "collapse",
            Self::RustfsLegacy => "rustfs-legacy",
        }
    }
}

/// Why a name was refused.
///
/// One variant per floor rule, so that a test can assert which rule fired rather than that
/// something did. A rule that shared a variant with another rule could be deleted without any
/// case noticing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameRejection {
    /// The name is empty once the policy has been applied.
    Empty,
    /// A bucket label shorter than the minimum.
    TooShort,
    /// Longer than the maximum, in bytes.
    TooLong,
    /// A NUL byte.
    Nul,
    /// A C0 control or DEL.
    ControlCharacter,
    /// A `..` segment, delimited by `/` or by `\`.
    TraversalSegment,
    /// A percent-escape spelling a separator or a `..` survived the single decode.
    EncodedSeparator,
    /// A drive-letter, UNC or double-slash-rooted shape: a location rather than a name.
    AbsoluteOrUnc,
    /// A separator in a label that may not contain one.
    PathSeparator,
    /// The bytes are not UTF-8 once decoded.
    InvalidUtf8,
    /// A character the naming rules in force do not admit.
    CharacterSet,
    /// A reserved prefix, suffix or address-shaped name.
    Reserved,
    /// A [`NameValidator`] refused it, with the reason it gave.
    Validator(&'static str),
}

impl NameRejection {
    /// The refusal a custom [`NameValidator`] returns.
    #[must_use]
    pub fn rejected_by_validator(reason: &'static str) -> Self {
        Self::Validator(reason)
    }

    /// A one-line reason, safe to put in an error body: it describes the rule, never the value.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Empty => "the name is empty",
            Self::TooShort => "the name is shorter than the minimum length",
            Self::TooLong => "the name is longer than the maximum length in bytes",
            Self::Nul => "the name contains a NUL byte",
            Self::ControlCharacter => "the name contains a control character",
            Self::TraversalSegment => "the name contains a dot-dot path segment",
            Self::EncodedSeparator => "the name still contains an encoded path separator after one decode",
            Self::AbsoluteOrUnc => "the name is spelled as an absolute or UNC path",
            Self::PathSeparator => "the name contains a path separator",
            Self::InvalidUtf8 => "the name is not valid UTF-8",
            Self::CharacterSet => "the name contains a character the naming rules do not admit",
            Self::Reserved => "the name uses a reserved form",
            Self::Validator(reason) => reason,
        }
    }

    /// The error code a refused *key* is answered with.
    ///
    /// Only the length rule has a code of its own; every other refusal is an argument the caller
    /// chose badly, and AWS answers those with `InvalidArgument`.
    #[must_use]
    pub fn key_error_code(&self) -> ErrorCode {
        match self {
            Self::TooLong => ErrorCode::KEY_TOO_LONG,
            _ => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// The error code a refused *bucket label* is answered with.
    ///
    /// Always `InvalidBucketName`: an SDK that has to distinguish a bad bucket name from any other
    /// bad parameter — `CreateBucket` is the one that must — cannot do it when both arrive as
    /// `InvalidArgument`.
    #[must_use]
    pub fn bucket_error_code(&self) -> ErrorCode {
        ErrorCode::INVALID_BUCKET_NAME
    }
}

impl std::fmt::Display for NameRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for NameRejection {}

/// A [`NameValidator`]'s answer.
///
/// There is deliberately no `Allow`. A validator that could allow would be a validator a
/// deployment could use to reopen the traversal the floor closed, and that is exactly the shape
/// the extension point exists to make unspellable — the framework AND-s this with the floor, so
/// the strongest thing a validator can say is "no opinion".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stricter {
    /// The validator adds nothing to the floor's verdict.
    NoOpinion,
    /// The validator refuses this name, for a reason of its own.
    Reject(NameRejection),
}

impl Stricter {
    /// Turns the answer into a result, so the caller can `?` it after the floor.
    ///
    /// # Errors
    ///
    /// The [`NameRejection`] the validator supplied.
    pub fn into_result(self) -> Result<(), NameRejection> {
        match self {
            Self::NoOpinion => Ok(()),
            Self::Reject(rejection) => Err(rejection),
        }
    }
}

/// A deployment's naming rules, which may narrow the floor and can never widen it.
///
/// Held as `Arc<dyn NameValidator>` by [`NamePolicy`]. Synchronous and allocation-free by
/// contract: it runs on the pre-authentication path, once per request, before anything about the
/// caller is known, so a validator that could await would turn an unauthenticated request into
/// work the deployment performs on the caller's behalf.
pub trait NameValidator: Send + Sync + 'static {
    /// Whether this deployment accepts a bucket label the floor already cleared.
    fn check_bucket(&self, name: &str) -> Stricter;

    /// Whether this deployment accepts an object key the floor already cleared.
    fn check_key(&self, key: &str) -> Stricter;
}

/// The built-in validator: the AWS general-purpose bucket naming rules, and no opinion on keys.
///
/// Replaceable. A deployment that serves clients which created buckets under looser rules can
/// install its own and reach those buckets again; the floor below it does not move.
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsNameValidator;

impl NameValidator for AwsNameValidator {
    fn check_bucket(&self, name: &str) -> Stricter {
        match aws_bucket_rules(name) {
            Ok(()) => Stricter::NoOpinion,
            Err(rejection) => Stricter::Reject(rejection),
        }
    }

    fn check_key(&self, _key: &str) -> Stricter {
        // An object key is opaque text on AWS. Everything worth refusing about one is a floor
        // rule, and an opinion here would be this project inventing a restriction AWS does not
        // have.
        Stricter::NoOpinion
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PermissiveNameValidator;

impl NameValidator for PermissiveNameValidator {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, _key: &str) -> Stricter {
        Stricter::NoOpinion
    }
}

/// The slash policy and the validator, together: everything the single normalisation point needs.
///
/// Cloning is one enum copy and one refcount bump, which is what lets the request path hold it by
/// value without the service becoming generic over the validator.
#[derive(Clone)]
pub struct NamePolicy {
    slash: SlashPolicy,
    validator: Arc<dyn NameValidator>,
}

impl NamePolicy {
    /// A policy over an explicit slash rule and validator.
    #[must_use]
    pub fn new(slash: SlashPolicy, validator: Arc<dyn NameValidator>) -> Self {
        Self { slash, validator }
    }

    /// The same policy with a different slash rule.
    #[must_use]
    pub fn with_slash_policy(self, slash: SlashPolicy) -> Self {
        Self { slash, ..self }
    }

    /// The same policy with a different validator.
    #[must_use]
    pub fn with_validator(self, validator: Arc<dyn NameValidator>) -> Self {
        match VALIDATOR_REPLACEABILITY {
            ValidatorReplaceabilityPolicy::CustomMayWidenAwsLayer => Self { validator, ..self },
            ValidatorReplaceabilityPolicy::IgnoreCustom => self,
        }
    }

    /// The slash rule in force.
    #[must_use]
    pub fn slash_policy(&self) -> SlashPolicy {
        self.slash
    }

    /// The validator in force.
    #[must_use]
    pub fn validator(&self) -> &dyn NameValidator {
        self.validator.as_ref()
    }
}

impl Default for NamePolicy {
    /// AWS slash semantics and the AWS bucket naming rules.
    fn default() -> Self {
        let slash = match DEFAULT_SLASH_POLICY {
            ContractSlashPolicy::AwsPreserve => SlashPolicy::AwsPreserve,
            ContractSlashPolicy::Collapse => SlashPolicy::Collapse,
        };
        let validator: Arc<dyn NameValidator> = match DEFAULT_BUCKET_VALIDATOR {
            DefaultValidatorPolicy::Aws => Arc::new(AwsNameValidator),
            DefaultValidatorPolicy::Permissive => Arc::new(PermissiveNameValidator),
        };
        Self { slash, validator }
    }
}

impl std::fmt::Debug for NamePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamePolicy")
            .field("slash", &self.slash)
            .finish_non_exhaustive()
    }
}

/// Percent-decodes a label exactly once.
///
/// The single decode is the whole security property: decoding until the value stops changing is
/// how `%252e%252e` becomes `..`, and there is no accessor anywhere that hands a caller a value
/// it could feed back in.
///
/// # Errors
///
/// [`NameRejection::InvalidUtf8`] when the decoded bytes are not UTF-8. Never lossy: replacing a
/// bad byte with U+FFFD invents a key the client did not send.
pub fn decode_once(encoded: &str) -> Result<String, NameRejection> {
    let decode = |value: &str| match DECODED_UTF8_POLICY {
        DecodedUtf8Policy::Strict => percent_decode_str(value)
            .decode_utf8()
            .map(std::borrow::Cow::into_owned)
            .map_err(|_| NameRejection::InvalidUtf8),
        DecodedUtf8Policy::Lossy => Ok(percent_decode_str(value).decode_utf8_lossy().into_owned()),
    };
    let mut decoded = decode(encoded)?;
    if PERCENT_DECODE_PASSES == PercentDecodePassesPolicy::UntilStable {
        loop {
            let next = decode(&decoded)?;
            if next == decoded {
                break;
            }
            decoded = next;
        }
    }
    Ok(decoded)
}

/// Whether a once-decoded value still spells a separator or a traversal in percent-encoding.
///
/// `%252e%252e` decodes once to `%2e%2e`. Accepting that as a literal key would leave a value in
/// storage which any consumer that decoded one more time would read as `..`, and "one more time"
/// is one careless helper away. Only the separator spellings are refused: `%25` on its own is an
/// ordinary key byte and `100%done` stays a legal key.
fn has_encoded_separator(decoded: &str) -> bool {
    if RESIDUAL_ENCODED_DANGER_POLICY == ResidualEncodedDangerPolicy::Allow {
        return false;
    }
    let lower = decoded.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e%2e")
}

/// Folds runs of slashes and drops a leading one. Linear in the length of the input.
fn collapse_slashes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_was_slash = false;
    for ch in value.chars() {
        if ch == '/' {
            if !previous_was_slash {
                out.push(ch);
            }
            previous_was_slash = true;
        } else {
            out.push(ch);
            previous_was_slash = false;
        }
    }
    match out.strip_prefix('/') {
        Some(rest) => rest.to_owned(),
        None => out,
    }
}

/// [`SlashPolicy::RustfsLegacy`]: folds a key that starts with `/` and leaves every other key as
/// sent. Linear in the length of the input.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS folds the slashes of a key only when the
/// key starts with one, so `PUT /bucket//a//b` stores `a/b` while `PUT /bucket/a//b` hands `a//b`
/// to storage unchanged; whether a run of slashes is data depends on where in the key it sits,
/// and the spelling a client sent is not the object it names. Kept so every key a RustFS client
/// stored stays reachable under the spelling it used. The intended future behaviour is
/// [`SlashPolicy::AwsPreserve`], which needs the objects stored under a folded spelling migrated
/// first.
fn fold_rooted_slashes(value: String) -> String {
    if !value.starts_with('/') {
        return value;
    }
    let mut folded = String::with_capacity(value.len());
    // A separator is written only once the next segment starts, so leading slashes and runs
    // between segments each leave at most one behind.
    let mut separator_pending = false;
    for ch in value.chars() {
        if ch == '/' {
            separator_pending = !folded.is_empty();
        } else {
            if separator_pending {
                folded.push('/');
                separator_pending = false;
            }
            folded.push(ch);
        }
    }
    // A key of slashes only keeps one, and a key that ended in a run of slashes keeps one of them.
    if folded.is_empty() || separator_pending {
        folded.push('/');
    }
    folded
}

/// The unconditional safety floor for an object key, applied to an already-decoded value.
///
/// Every rule here is one a [`NameValidator`] cannot switch off. The list is short on purpose: an
/// object key is opaque text, and each of these is either a byte no client can usefully name or a
/// spelling that means something to a filesystem.
///
/// # Errors
///
/// The [`NameRejection`] naming the rule that fired, first rule first.
pub fn floor_check_key(key: &str) -> Result<(), NameRejection> {
    if key.is_empty() {
        return Err(NameRejection::Empty);
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(NameRejection::TooLong);
    }
    if key.contains('\0') {
        return Err(NameRejection::Nul);
    }
    // C0 and DEL. Tab, newline and carriage return are included: AWS admits them in a key, and
    // this gateway does not, because a key holding one is a key no log line, no XML document and
    // no shell pipeline can carry unambiguously. Recorded as a divergence in
    // `model/overlays/quirks/naming.toml`.
    if CLIENT_INGRESS_FORBIDDEN_CODEPOINTS == ClientIngressCodepointPolicy::NulC0AndDel && key.chars().any(|c| c.is_control()) {
        return Err(NameRejection::ControlCharacter);
    }
    // Two or more leading slashes is the UNC spelling; exactly one is the AWS `//key` spelling and
    // is legal. A drive letter is a location on the platform the storage layer may be running on.
    if ABSOLUTE_OR_UNC_POLICY == AbsoluteOrUncPolicy::Reject
        && (key.starts_with("//") || key.starts_with('\\') || is_drive_rooted(key))
    {
        return Err(NameRejection::AbsoluteOrUnc);
    }
    // Split on both separators: on Windows a backslash delimits a segment, so `a\..\b` is the same
    // traversal as `a/../b` and refusing only one of the two spellings refuses neither.
    let has_traversal = match TRAVERSAL_DELIMITERS {
        TraversalDelimitersPolicy::SlashAndBackslash => key.split(['/', '\\']).any(|segment| segment == ".."),
        TraversalDelimitersPolicy::SlashOnly => key.split('/').any(|segment| segment == ".."),
    };
    if has_traversal {
        return Err(NameRejection::TraversalSegment);
    }
    Ok(())
}

/// Whether a key begins with a Windows drive-letter root such as `C:\` or `c:/`.
fn is_drive_rooted(key: &str) -> bool {
    let mut bytes = key.bytes();
    let (Some(letter), Some(colon), Some(separator)) = (bytes.next(), bytes.next(), bytes.next()) else {
        return false;
    };
    letter.is_ascii_alphabetic() && colon == b':' && (separator == b'\\' || separator == b'/')
}

/// The unconditional safety floor for a bucket label.
///
/// Deliberately narrower than the AWS rules: uppercase, underscores and leading dots are refused
/// by [`AwsNameValidator`] and may be accepted by a deployment that replaces it. What is here is
/// what no deployment may accept — a label that could be read as a path, carry a control byte, or
/// sit outside the length AWS itself enforces.
///
/// # Errors
///
/// The [`NameRejection`] naming the rule that fired.
pub fn floor_check_bucket(name: &str) -> Result<(), NameRejection> {
    if name.is_empty() {
        return Err(NameRejection::Empty);
    }
    if name.len() < MIN_BUCKET_BYTES {
        return Err(NameRejection::TooShort);
    }
    if name.len() > MAX_BUCKET_BYTES {
        return Err(NameRejection::TooLong);
    }
    if name.contains('\0') {
        return Err(NameRejection::Nul);
    }
    if name.contains(['/', '\\']) {
        return Err(NameRejection::PathSeparator);
    }
    if name.split(['/', '\\', '.']).any(|segment| segment == "..") {
        return Err(NameRejection::TraversalSegment);
    }
    // A bucket label is never percent-decoded — the naming rules admit only characters that need
    // no escaping — so a `%` here is a spelling no client produces and a decode nobody performs.
    if name.contains('%') {
        return Err(NameRejection::EncodedSeparator);
    }
    // ASCII graphic only: this rules out every control byte and the space in one predicate, and
    // leaves every character any real bucket naming scheme uses.
    if !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(NameRejection::CharacterSet);
    }
    Ok(())
}

/// The AWS general-purpose bucket naming rules, as [`AwsNameValidator`] applies them.
///
/// # Errors
///
/// The [`NameRejection`] naming the rule that fired.
pub fn aws_bucket_rules(name: &str) -> Result<(), NameRejection> {
    if !(MIN_BUCKET_BYTES..=MAX_BUCKET_BYTES).contains(&name.len()) {
        return Err(if name.len() < MIN_BUCKET_BYTES {
            NameRejection::TooShort
        } else {
            NameRejection::TooLong
        });
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(NameRejection::CharacterSet);
    }
    let first_last_ok = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !first_last_ok(name.bytes().next()) || !first_last_ok(name.bytes().next_back()) {
        return Err(NameRejection::CharacterSet);
    }
    if name.contains("..") {
        return Err(NameRejection::CharacterSet);
    }
    if is_ipv4_shaped(name) {
        return Err(NameRejection::Reserved);
    }
    if name.starts_with("xn--") || name.starts_with("sthree-") {
        return Err(NameRejection::Reserved);
    }
    // `--x-s3` and `--ol-s3` name S3 Express and Object Lambda buckets, whose naming rules are not
    // these. Accepting one here would route a directory bucket through the general-purpose rules.
    if name.ends_with("-s3alias") || name.ends_with("--ol-s3") || name.ends_with("--x-s3") {
        return Err(NameRejection::Reserved);
    }
    Ok(())
}

/// Whether the name is four dot-separated decimal octets, which would make a path-style URL
/// ambiguous with an address.
fn is_ipv4_shaped(name: &str) -> bool {
    let mut labels = 0usize;
    for label in name.split('.') {
        labels = labels.saturating_add(1);
        let valid = !label.is_empty()
            && label.len() <= 3
            && label.bytes().all(|b| b.is_ascii_digit())
            && label.parse::<u16>().is_ok_and(|value| value <= 255);
        if !valid {
            return false;
        }
    }
    labels == 4
}

/// **The single normalisation.** Turns one percent-encoded path label into the key bytes every
/// stage downstream reads.
///
/// Returns the normalised key. The caller keeps the encoded spelling separately, because the
/// signature covers what arrived and not what this produced.
///
/// # Errors
///
/// The [`NameRejection`] naming the first rule that refused it, in the order documented at the top
/// of this module.
pub(crate) fn normalize_key(encoded: &str, policy: &NamePolicy) -> Result<String, NameRejection> {
    let decoded = decode_once(encoded)?;
    if has_encoded_separator(&decoded) {
        return Err(NameRejection::EncodedSeparator);
    }
    let slashes = match policy.slash_policy() {
        SlashPolicy::AwsPreserve => decoded,
        SlashPolicy::Collapse => collapse_slashes(&decoded),
        SlashPolicy::RustfsLegacy => fold_rooted_slashes(decoded),
    };
    let unicode = match UNICODE_NORMALIZATION {
        UnicodeNormalizationPolicy::None => slashes,
        UnicodeNormalizationPolicy::Nfc => slashes.nfc().collect(),
    };
    let normalised = match CASE_FOLDING {
        CaseFoldingPolicy::None => unicode,
        CaseFoldingPolicy::Lowercase => unicode.to_lowercase(),
    };
    // Floor first, validator second, and the two are AND-ed: a validator has no way to reach a
    // value the floor already refused, because the floor returned before it was consulted.
    check_key_policy(&normalised, policy)?;
    Ok(normalised)
}

/// The same, for a value some other reader already decoded — a body element or a query parameter.
///
/// No decode happens here: a second decode of an already-decoded value is the double-decode bug
/// this module exists to prevent, so the caller's decode is the only one and this applies the
/// floor to its result.
///
/// # Errors
///
/// The [`NameRejection`] naming the rule that refused it.
pub(crate) fn check_decoded_key(decoded: &str, policy: &NamePolicy) -> Result<(), NameRejection> {
    check_key_policy(decoded, policy)
}

/// The single normalisation for a bucket label: floor, then validator.
///
/// A bucket label is not percent-decoded and no slash policy applies to it — one containing a
/// slash is not a bucket label at all, which is a floor rule rather than a normalisation.
///
/// # Errors
///
/// The [`NameRejection`] naming the rule that refused it.
pub(crate) fn check_bucket(name: &str, policy: &NamePolicy) -> Result<(), NameRejection> {
    match VALIDATOR_AUTHORITY {
        ValidatorAuthorityPolicy::NarrowOnlyAfterFloor => {
            floor_check_bucket(name)?;
            policy.validator().check_bucket(name).into_result()
        }
        ValidatorAuthorityPolicy::CustomMayBypassFloor => policy.validator().check_bucket(name).into_result(),
    }
}

fn check_key_policy(key: &str, policy: &NamePolicy) -> Result<(), NameRejection> {
    match VALIDATOR_AUTHORITY {
        ValidatorAuthorityPolicy::NarrowOnlyAfterFloor => {
            floor_check_key(key)?;
            policy.validator().check_key(key).into_result()
        }
        ValidatorAuthorityPolicy::CustomMayBypassFloor => policy.validator().check_key(key).into_result(),
    }
}

pub(crate) fn stored_key_rejects_control(key: &str) -> bool {
    STORED_LEGACY_CONTROL_POLICY == StoredLegacyControlPolicy::RejectAllControls && key.chars().any(char::is_control)
}
