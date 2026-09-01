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

//! Runtime-owned XML extension fields and persisted-document rewrite safety.
//!
//! Responsible for: typed extension vtables, borrowed per-codec policy, deterministic known-sibling
//! insertion, and preserving bytes when persisted XML cannot be decoded completely.
//! NOT responsible for: operation registration, XML parsing limits, or any concrete vendor field.
//! Upstream: `rustfs-gateway-xml`. Downstream: generated/static parent codecs and persistence
//! adapters that explicitly opt into an extension point.

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use rustfs_gateway_xml::{XmlNode, XmlWriter};

type ErasedValue = dyn Any + Send + Sync;
type EncodeFn = fn(&ErasedValue, &mut XmlWriter) -> Result<(), ExtError>;
type DecodeFn = fn(&XmlNode) -> Result<Box<ErasedValue>, ExtError>;

/// One typed XML element registered below a static parent shape.
pub trait ExtField: Any + Send + Sync + Sized + 'static {
    /// Static parent shape local name.
    const PARENT: &'static str;
    /// XML local name claimed below the parent.
    const LOCAL_NAME: &'static str;
    /// Known sibling whose schema slot immediately precedes this field.
    const INSERT_AFTER: &'static str;

    /// Decodes one complete extension element.
    fn decode_xml(node: &XmlNode) -> Result<Self, ExtError>;

    /// Encodes the complete extension element into a scratch writer.
    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), ExtError>;
}

/// A fail-closed extension registration, decode, encode, or persistence error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtError {
    /// Two types claimed one parent/local-name pair.
    DuplicateRegistration {
        /// Parent claimed by both registrations.
        parent: &'static str,
        /// Local name claimed by both registrations.
        local_name: &'static str,
    },
    /// The active policy refused an unknown child.
    UnknownElement(String),
    /// A vtable and stored value disagreed about their concrete type.
    TypeMismatch,
    /// A concrete extension omitted a required member.
    MissingRequired(&'static str),
    /// A concrete extension carried an invalid member value.
    InvalidValue(&'static str),
    /// An extension encoder did not produce one well-formed element.
    InvalidXml,
    /// The static parent codec rejected a known member or document shape.
    ParentCodec,
    /// A parent codec did not declare the extension's known-sibling slot.
    UnsupportedInsertionSlot {
        /// Static parent shape.
        parent: &'static str,
        /// Extension element local name.
        local_name: &'static str,
        /// Missing known sibling.
        insert_after: &'static str,
    },
    /// A persisted read was incomplete, so replacement would discard bytes.
    PersistedRewriteBlocked,
}

impl fmt::Display for ExtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRegistration { parent, local_name } => {
                write!(formatter, "duplicate extension registration for {parent}.{local_name}")
            }
            Self::UnknownElement(name) => write!(formatter, "unknown XML element {name}"),
            Self::TypeMismatch => formatter.write_str("extension type did not match its registered vtable"),
            Self::MissingRequired(name) => write!(formatter, "missing required extension member {name}"),
            Self::InvalidValue(name) => write!(formatter, "invalid extension member {name}"),
            Self::InvalidXml => formatter.write_str("extension encoder produced invalid XML"),
            Self::ParentCodec => formatter.write_str("the static parent XML codec rejected the document"),
            Self::UnsupportedInsertionSlot {
                parent,
                local_name,
                insert_after,
            } => write!(
                formatter,
                "extension {parent}.{local_name} requires unsupported insertion slot after {insert_after}"
            ),
            Self::PersistedRewriteBlocked => {
                formatter.write_str("persisted XML was not decoded completely; replacement is blocked")
            }
        }
    }
}

impl std::error::Error for ExtError {}

/// Unknown-child behavior selected for one borrowed codec invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownElementPolicy {
    /// Decode registered extension fields and reject every unregistered child.
    AllowRegistered,
    /// Reject every unknown child, including registered extension fields.
    Deny,
    /// Decode registered fields and ignore other already-bounded subtrees.
    Lenient,
}

struct ExtVTable {
    local_name: &'static str,
    insert_after: &'static str,
    type_id: TypeId,
    encode: EncodeFn,
    decode: DecodeFn,
}

/// Runtime-owned extension registry and unknown-child policy.
///
/// Parent codecs borrow this value for one decode or encode. No process-global registration or
/// request-carrier field is involved.
pub struct CodecPolicy {
    ext: BTreeMap<&'static str, Vec<ExtVTable>>,
    unknown: UnknownElementPolicy,
}

impl CodecPolicy {
    /// The default for security-relevant XML: only explicitly registered extensions may pass.
    #[must_use]
    pub fn security_relevant() -> Self {
        Self::new(UnknownElementPolicy::AllowRegistered)
    }

    /// Creates an empty policy with explicit unknown-child behavior.
    #[must_use]
    pub fn new(unknown: UnknownElementPolicy) -> Self {
        Self {
            ext: BTreeMap::new(),
            unknown,
        }
    }

    /// Registers one typed extension and freezes deterministic slot/name order.
    pub fn register<E: ExtField>(&mut self) -> Result<(), ExtError> {
        let entries = self.ext.entry(E::PARENT).or_default();
        if entries.iter().any(|entry| entry.local_name == E::LOCAL_NAME) {
            return Err(ExtError::DuplicateRegistration {
                parent: E::PARENT,
                local_name: E::LOCAL_NAME,
            });
        }
        entries.push(ExtVTable {
            local_name: E::LOCAL_NAME,
            insert_after: E::INSERT_AFTER,
            type_id: TypeId::of::<E>(),
            encode: encode_erased::<E>,
            decode: decode_erased::<E>,
        });
        entries.sort_by_key(|entry| (entry.insert_after, entry.local_name));
        Ok(())
    }

    /// Returns this invocation's unknown-child behavior.
    #[must_use]
    pub const fn unknown_elements(&self) -> UnknownElementPolicy {
        self.unknown
    }

    /// Dispatches one child the static parent codec does not know.
    pub fn decode_unknown(&self, parent: &'static str, node: &XmlNode, extensions: &mut Extensions) -> Result<(), ExtError> {
        let registered = self
            .ext
            .get(parent)
            .and_then(|entries| entries.iter().find(|entry| entry.local_name == node.name));
        match (self.unknown, registered) {
            (UnknownElementPolicy::Deny, _) | (UnknownElementPolicy::AllowRegistered, None) => {
                Err(ExtError::UnknownElement(node.name.clone()))
            }
            (UnknownElementPolicy::Lenient, None) => Ok(()),
            (UnknownElementPolicy::AllowRegistered | UnknownElementPolicy::Lenient, Some(entry)) => {
                let value = (entry.decode)(node)?;
                extensions.insert_erased(entry.type_id, value);
                Ok(())
            }
        }
    }

    /// Validates that every registered insertion slot is implemented by the parent codec.
    pub fn validate_slots(&self, parent: &'static str, implemented: &[&str]) -> Result<(), ExtError> {
        for entry in self.ext.get(parent).into_iter().flatten() {
            if !implemented.contains(&entry.insert_after) {
                return Err(ExtError::UnsupportedInsertionSlot {
                    parent,
                    local_name: entry.local_name,
                    insert_after: entry.insert_after,
                });
            }
        }
        Ok(())
    }

    /// Emits registered values immediately after one known sibling.
    ///
    /// Each vtable writes into a scratch buffer. Only a complete, well-formed element is appended,
    /// so an extension error cannot expose a partial parent document.
    pub fn encode_after(
        &self,
        parent: &'static str,
        sibling: &str,
        extensions: &Extensions,
        writer: &mut XmlWriter,
    ) -> Result<(), ExtError> {
        for entry in self.ext.get(parent).into_iter().flatten() {
            if entry.insert_after != sibling {
                continue;
            }
            let Some(value) = extensions.get_erased(entry.type_id) else {
                continue;
            };
            let mut scratch = XmlWriter::fragment();
            (entry.encode)(value, &mut scratch)?;
            writer.append_fragment(&scratch.finish()).map_err(|_| ExtError::InvalidXml)?;
        }
        Ok(())
    }
}

fn encode_erased<E: ExtField>(value: &ErasedValue, writer: &mut XmlWriter) -> Result<(), ExtError> {
    value.downcast_ref::<E>().ok_or(ExtError::TypeMismatch)?.encode_xml(writer)
}

fn decode_erased<E: ExtField>(node: &XmlNode) -> Result<Box<ErasedValue>, ExtError> {
    E::decode_xml(node).map(|value| Box::new(value) as Box<ErasedValue>)
}

/// Per-document extension values indexed by their contractual concrete type.
#[derive(Default)]
pub struct Extensions(HashMap<TypeId, Box<ErasedValue>>);

impl Extensions {
    /// Returns one registered extension value, or `None` on a contractual miss.
    #[must_use]
    pub fn get<E: ExtField>(&self) -> Option<&E> {
        self.0.get(&TypeId::of::<E>()).and_then(|value| value.downcast_ref::<E>())
    }

    /// Inserts one typed extension, returning the previous value of the same type.
    pub fn insert<E: ExtField>(&mut self, value: E) -> Option<E> {
        self.0
            .insert(TypeId::of::<E>(), Box::new(value))
            .and_then(|old| old.downcast::<E>().ok().map(|boxed| *boxed))
    }

    fn get_erased(&self, type_id: TypeId) -> Option<&ErasedValue> {
        self.0.get(&type_id).map(Box::as_ref)
    }

    fn insert_erased(&mut self, type_id: TypeId, value: Box<ErasedValue>) {
        self.0.insert(type_id, value);
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Extensions").field("len", &self.0.len()).finish()
    }
}

/// A persisted XML read that always retains its original bytes.
///
/// A failed or incomplete decode can be inspected, but it cannot be converted into replacement
/// bytes. This prevents a read-modify-write path from translating a registration miss or parse
/// failure into an absent configuration.
#[derive(Debug)]
pub struct PersistedXml<T> {
    original: Vec<u8>,
    decoded: Result<T, ExtError>,
    rewrite_allowed: bool,
}

impl<T> PersistedXml<T> {
    /// Decodes while retaining the exact source bytes regardless of outcome.
    #[must_use]
    pub fn decode(original: Vec<u8>, decode: impl FnOnce(&[u8]) -> Result<T, ExtError>) -> Self {
        let decoded = decode(&original);
        let rewrite_allowed = decoded.is_ok();
        Self {
            original,
            decoded,
            rewrite_allowed,
        }
    }

    /// Decodes a persisted document for runtime decisions without enabling typed replacement.
    ///
    /// This is the bridge for a family whose read path is production-ready before its migration
    /// writer is. A successful decode remains observable through [`Self::value`], while
    /// [`Self::replacement`] stays fail-closed until the family's independently verified writer
    /// is installed.
    #[must_use]
    pub fn decode_read_only(original: Vec<u8>, decode: impl FnOnce(&[u8]) -> Result<T, ExtError>) -> Self {
        let decoded = decode(&original);
        Self {
            original,
            decoded,
            rewrite_allowed: false,
        }
    }

    /// Returns the exact persisted bytes supplied to [`Self::decode`].
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Returns the complete decoded value or the refusal that preserved the original bytes.
    pub fn value(&self) -> Result<&T, &ExtError> {
        self.decoded.as_ref()
    }

    /// Returns the complete decoded value mutably, or the refusal that preserved the source.
    pub fn value_mut(&mut self) -> Result<&mut T, &mut ExtError> {
        self.decoded.as_mut()
    }

    /// Accepts replacement bytes only after a complete decode.
    pub fn replacement(&self, encoded: Vec<u8>) -> Result<Vec<u8>, ExtError> {
        if self.decoded.is_ok() && self.rewrite_allowed {
            Ok(encoded)
        } else {
            Err(ExtError::PersistedRewriteBlocked)
        }
    }
}
