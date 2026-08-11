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

//! Runtime extension registration and TypeId-indexed request storage.
//!
//! This module owns policy lookup, not XML shape parsing. The static parent codec consumes its
//! vtables, and dialect-field implementations provide the registered encode/decode functions.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;

use crate::{XmlError, XmlReader, XmlWriter};

/// One typed XML element that can be registered under a static parent codec.
pub trait ExtField: Any + Send + Sync + 'static + Sized {
    /// Static parent shape local name.
    const PARENT: &'static str;
    /// XML local name claimed under the parent.
    const LOCAL_NAME: &'static str;
    /// Known sibling whose schema slot immediately precedes this field.
    const INSERT_AFTER: &'static str;

    /// Encodes this field, including its outer element.
    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), XmlError>;

    /// Decodes this field after its start element has been consumed.
    fn decode_xml(reader: &mut XmlReader<'_>) -> Result<Self, XmlError>;
}

type ErasedValue = dyn Any + Send + Sync;
type EncodeFn = fn(&ErasedValue, &mut XmlWriter) -> Result<(), XmlError>;
type DecodeFn = for<'input> fn(&mut XmlReader<'input>) -> Result<Box<ErasedValue>, XmlError>;

/// The object-safe function table generated for one [`ExtField`] registration.
pub struct ExtVTable {
    local_name: &'static str,
    insert_after: &'static str,
    type_id: TypeId,
    encode: EncodeFn,
    decode: DecodeFn,
}

impl ExtVTable {
    pub(crate) fn insert_after(&self) -> &'static str {
        self.insert_after
    }

    pub(crate) fn local_name(&self) -> &'static str {
        self.local_name
    }

    pub(crate) fn type_id(&self) -> TypeId {
        self.type_id
    }

    pub(crate) fn encode(&self, value: &ErasedValue, writer: &mut XmlWriter) -> Result<(), XmlError> {
        (self.encode)(value, writer)
    }

    pub(crate) fn decode(&self, reader: &mut XmlReader<'_>) -> Result<Box<ErasedValue>, XmlError> {
        (self.decode)(reader)
    }
}

/// Unknown-element behavior selected for one codec invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownPolicy {
    /// Decode registered extensions and reject every other unknown element.
    AllowRegistered,
    /// Reject every unknown element, including registered extensions.
    Deny,
    /// Decode registered extensions and skip every other unknown subtree.
    Lenient,
}

/// Resource caps enforced by [`XmlReader`](crate::XmlReader).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmlLimits {
    /// Maximum open-element depth.
    pub max_depth: u16,
    /// Maximum number of start and empty elements.
    pub max_elements: u32,
    /// Maximum input body length.
    pub max_bytes: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_depth: 50,
            max_elements: 10_000,
            max_bytes: 2 << 20,
        }
    }
}

/// Runtime-owned extension registry and unknown-element policy.
pub struct CodecPolicy {
    ext: HashMap<&'static str, Vec<ExtVTable>>,
    unknown: UnknownPolicy,
    limits: XmlLimits,
}

impl CodecPolicy {
    /// Creates a policy with default XML resource limits.
    #[must_use]
    pub fn new(unknown: UnknownPolicy) -> Self {
        Self::with_limits(unknown, XmlLimits::default())
    }

    /// Creates a policy with explicit XML resource limits.
    #[must_use]
    pub fn with_limits(unknown: UnknownPolicy, limits: XmlLimits) -> Self {
        Self {
            ext: HashMap::new(),
            unknown,
            limits,
        }
    }

    /// Registers one extension, rejecting duplicate parent/local-name claims.
    pub fn register<E: ExtField>(&mut self) -> Result<(), XmlError> {
        let entries = self.ext.entry(E::PARENT).or_default();
        if entries.iter().any(|entry| entry.local_name == E::LOCAL_NAME) {
            return Err(XmlError::DuplicateRegistration {
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
        Ok(())
    }

    /// Returns the stable registration-order slice for a parent shape.
    #[must_use]
    pub fn ext_fields_for(&self, parent: &'static str) -> &[ExtVTable] {
        self.ext.get(parent).map(Vec::as_slice).unwrap_or_default()
    }

    pub(crate) fn ext_field(&self, parent: &'static str, local_name: &str) -> Option<&ExtVTable> {
        self.ext_fields_for(parent)
            .iter()
            .find(|entry| entry.local_name == local_name)
    }

    pub(crate) fn unknown(&self) -> UnknownPolicy {
        self.unknown
    }

    pub(crate) fn limits(&self) -> XmlLimits {
        self.limits
    }
}

fn encode_erased<E: ExtField>(value: &ErasedValue, writer: &mut XmlWriter) -> Result<(), XmlError> {
    value.downcast_ref::<E>().ok_or(XmlError::TypeMismatch)?.encode_xml(writer)
}

fn decode_erased<E: ExtField>(reader: &mut XmlReader<'_>) -> Result<Box<ErasedValue>, XmlError> {
    E::decode_xml(reader).map(|value| Box::new(value) as Box<ErasedValue>)
}

/// Per-request extension values indexed by their contractual [`TypeId`].
#[derive(Default)]
pub struct Extensions(HashMap<TypeId, Box<ErasedValue>>);

impl Extensions {
    /// Returns the value of a requested extension type, or `None` on a contractual miss.
    #[must_use]
    pub fn get<E: ExtField>(&self) -> Option<&E> {
        self.0.get(&TypeId::of::<E>()).and_then(|value| value.downcast_ref::<E>())
    }

    /// Inserts one typed extension and returns the prior value of that same type, if present.
    pub fn insert<E: ExtField>(&mut self, value: E) -> Option<E> {
        self.0
            .insert(TypeId::of::<E>(), Box::new(value))
            .and_then(|old| old.downcast::<E>().ok().map(|boxed| *boxed))
    }

    pub(crate) fn get_erased(&self, type_id: TypeId) -> Option<&ErasedValue> {
        self.0.get(&type_id).map(Box::as_ref)
    }

    pub(crate) fn insert_erased(&mut self, type_id: TypeId, value: Box<ErasedValue>) {
        self.0.insert(type_id, value);
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Extensions").field("len", &self.0.len()).finish()
    }
}
