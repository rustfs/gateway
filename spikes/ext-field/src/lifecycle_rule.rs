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

//! Hand-written stand-in for a generated static `LifecycleRule` codec.
//!
//! This file owns only known fields and vtable call sites. It must not name the dialect type;
//! `CodecPolicy` and registered implementations are its upstream, while tests simulate codegen's
//! downstream use.

use std::io::Read;

use crate::{
    CodecPolicy, Extensions, UnknownPolicy, XmlError, XmlEvent, XmlReader, XmlWriter, read_text_content, skip_element_content,
    write_end, write_start, write_text_element,
};

const PARENT: &str = "LifecycleRule";

/// Minimal typed lifecycle rule used by the single-field spike.
#[derive(Debug)]
pub struct LifecycleRule {
    /// Optional rule identifier.
    pub id: Option<String>,
    /// Required lifecycle status.
    pub status: String,
    /// Optional known expiration day count.
    pub expiration_days: Option<u32>,
    /// Runtime-indexed dialect fields.
    pub ext: Extensions,
}

impl LifecycleRule {
    /// Creates a rule containing only its required status.
    #[must_use]
    pub fn new(status: impl Into<String>) -> Self {
        Self {
            id: None,
            status: status.into(),
            expiration_days: None,
            ext: Extensions::default(),
        }
    }

    /// Decodes one `<Rule>` document with a runtime policy.
    pub fn decode_xml(input: &[u8], policy: &CodecPolicy) -> Result<Self, XmlError> {
        Self::decode_reader(input, policy)
    }

    /// Reads at most `max_bytes + 1` bytes from a request body and decodes one `<Rule>` document.
    pub fn decode_reader<R: Read>(mut body: R, policy: &CodecPolicy) -> Result<Self, XmlError> {
        let limits = policy.limits();
        let read_cap = u64::try_from(limits.max_bytes).map_or(u64::MAX, |limit| limit.saturating_add(1));
        let mut bounded = (&mut body).take(read_cap);
        let mut input = Vec::new();
        bounded
            .read_to_end(&mut input)
            .map_err(|error| XmlError::Io(error.to_string()))?;
        if input.len() > limits.max_bytes {
            return Err(XmlError::LimitExceeded(crate::LimitKind::Bytes));
        }
        Self::decode_buffered(&input, policy)
    }

    fn decode_buffered(input: &[u8], policy: &CodecPolicy) -> Result<Self, XmlError> {
        let mut reader = XmlReader::new(input, policy.limits())?;
        expect_root(&mut reader)?;
        let mut rule = Self::new("");
        loop {
            match reader.next_event()? {
                XmlEvent::Start(name) if name == "ID" => rule.id = Some(read_text_content(&mut reader, "ID")?),
                XmlEvent::Start(name) if name == "Status" => rule.status = read_text_content(&mut reader, "Status")?,
                XmlEvent::Start(name) if name == "Expiration" => {
                    rule.expiration_days = Some(read_expiration(&mut reader, policy)?)
                }
                XmlEvent::Start(name) => read_unknown(&mut reader, policy, &mut rule.ext, &name)?,
                XmlEvent::Empty(name) => read_empty_unknown(policy, &name)?,
                XmlEvent::End(name) if name == "Rule" => break,
                XmlEvent::End(name) => return Err(XmlError::Xml(format!("unexpected </{name}> in <Rule>"))),
                XmlEvent::Text(text) if text.trim().is_empty() => {}
                XmlEvent::Text(_) => return Err(XmlError::Xml("text is not allowed directly under <Rule>".to_owned())),
                XmlEvent::Eof => return Err(XmlError::Xml("unexpected EOF in <Rule>".to_owned())),
            }
        }
        if rule.status.is_empty() {
            return Err(XmlError::MissingRequired("Status"));
        }
        expect_eof(&mut reader)?;
        Ok(rule)
    }

    /// Encodes known fields and invokes extension vtables at their declared schema slot.
    pub fn encode_xml(&self, policy: &CodecPolicy) -> Result<Vec<u8>, XmlError> {
        if self.status.is_empty() {
            return Err(XmlError::MissingRequired("Status"));
        }
        let mut writer = XmlWriter::new(Vec::new());
        write_start(&mut writer, "Rule")?;
        if let Some(days) = self.expiration_days {
            write_start(&mut writer, "Expiration")?;
            write_text_element(&mut writer, "Days", &days.to_string())?;
            write_end(&mut writer, "Expiration")?;
        }
        for vtable in policy.ext_fields_for(PARENT) {
            if vtable.insert_after() != "Expiration" {
                return Err(XmlError::Extension(format!(
                    "unsupported insertion slot {}.{} after {}",
                    PARENT,
                    vtable.local_name(),
                    vtable.insert_after()
                )));
            }
            if let Some(value) = self.ext.get_erased(vtable.type_id()) {
                vtable.encode(value, &mut writer)?;
            }
        }
        if let Some(id) = &self.id {
            write_text_element(&mut writer, "ID", id)?;
        }
        write_text_element(&mut writer, "Status", &self.status)?;
        write_end(&mut writer, "Rule")?;
        Ok(writer.into_inner())
    }
}

fn expect_root(reader: &mut XmlReader<'_>) -> Result<(), XmlError> {
    loop {
        match reader.next_event()? {
            XmlEvent::Start(name) if name == "Rule" => return Ok(()),
            XmlEvent::Start(name) | XmlEvent::Empty(name) => return Err(XmlError::UnknownElement(name)),
            XmlEvent::Text(text) if text.trim().is_empty() => {}
            XmlEvent::Text(_) | XmlEvent::End(_) | XmlEvent::Eof => {
                return Err(XmlError::Xml("expected <Rule> root element".to_owned()));
            }
        }
    }
}

fn expect_eof(reader: &mut XmlReader<'_>) -> Result<(), XmlError> {
    loop {
        match reader.next_event()? {
            XmlEvent::Text(text) if text.trim().is_empty() => {}
            XmlEvent::Eof => return Ok(()),
            _ => return Err(XmlError::Xml("content follows </Rule>".to_owned())),
        }
    }
}

fn read_expiration(reader: &mut XmlReader<'_>, policy: &CodecPolicy) -> Result<u32, XmlError> {
    let mut days = None;
    loop {
        match reader.next_event()? {
            XmlEvent::Start(name) if name == "Days" => {
                let text = read_text_content(reader, "Days")?;
                days = Some(text.parse::<u32>().map_err(|error| XmlError::Xml(error.to_string()))?);
            }
            XmlEvent::Start(name) => handle_unregistered(reader, policy, &name)?,
            XmlEvent::Empty(name) => read_empty_unknown(policy, &name)?,
            XmlEvent::End(name) if name == "Expiration" => return days.ok_or(XmlError::MissingRequired("Days")),
            XmlEvent::End(name) => return Err(XmlError::Xml(format!("unexpected </{name}> in <Expiration>"))),
            XmlEvent::Text(text) if text.trim().is_empty() => {}
            XmlEvent::Text(_) => return Err(XmlError::Xml("text is not allowed directly under <Expiration>".to_owned())),
            XmlEvent::Eof => return Err(XmlError::Xml("unexpected EOF in <Expiration>".to_owned())),
        }
    }
}

fn read_unknown(
    reader: &mut XmlReader<'_>,
    policy: &CodecPolicy,
    extensions: &mut Extensions,
    local_name: &str,
) -> Result<(), XmlError> {
    if policy.unknown() != UnknownPolicy::Deny
        && let Some(vtable) = policy.ext_field(PARENT, local_name)
    {
        let value = vtable.decode(reader)?;
        extensions.insert_erased(vtable.type_id(), value);
        return Ok(());
    }
    handle_unregistered(reader, policy, local_name)
}

fn handle_unregistered(reader: &mut XmlReader<'_>, policy: &CodecPolicy, local_name: &str) -> Result<(), XmlError> {
    match policy.unknown() {
        UnknownPolicy::Lenient => skip_element_content(reader),
        UnknownPolicy::AllowRegistered | UnknownPolicy::Deny => Err(XmlError::UnknownElement(local_name.to_owned())),
    }
}

fn read_empty_unknown(policy: &CodecPolicy, local_name: &str) -> Result<(), XmlError> {
    match policy.unknown() {
        UnknownPolicy::Lenient => Ok(()),
        UnknownPolicy::AllowRegistered | UnknownPolicy::Deny => Err(XmlError::UnknownElement(local_name.to_owned())),
    }
}
