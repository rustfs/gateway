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

//! The only dialect field implemented by this spike.
//!
//! It owns the field's typed XML body, not its parent rule. `CodecPolicy` erases it into a vtable,
//! and the static lifecycle codec calls that vtable without importing this module's type.

use crate::{ExtField, XmlError, XmlEvent, XmlReader, XmlWriter, read_text_content, write_end, write_start, write_text_element};

/// MinIO's delete-marker-expiration day count under a lifecycle rule.
#[derive(Debug, Eq, PartialEq)]
pub struct DelMarkerExpiration {
    /// Number of days after which an expired delete marker is removed.
    pub days: u32,
}

impl ExtField for DelMarkerExpiration {
    const PARENT: &'static str = "LifecycleRule";
    const LOCAL_NAME: &'static str = "DelMarkerExpiration";
    const INSERT_AFTER: &'static str = "Expiration";

    fn encode_xml(&self, writer: &mut XmlWriter) -> Result<(), XmlError> {
        write_start(writer, Self::LOCAL_NAME)?;
        write_text_element(writer, "Days", &self.days.to_string())?;
        write_end(writer, Self::LOCAL_NAME)
    }

    fn decode_xml(reader: &mut XmlReader<'_>) -> Result<Self, XmlError> {
        let mut days = None;
        loop {
            match reader.next_event()? {
                XmlEvent::Start(name) if name == "Days" => {
                    let text = read_text_content(reader, "Days")?;
                    days = Some(text.parse::<u32>().map_err(|error| XmlError::Extension(error.to_string()))?);
                }
                XmlEvent::Start(name) | XmlEvent::Empty(name) => return Err(XmlError::UnknownElement(name)),
                XmlEvent::End(name) if name == Self::LOCAL_NAME => {
                    return days
                        .map(|days| Self { days })
                        .ok_or(XmlError::MissingRequired("DelMarkerExpiration.Days"));
                }
                XmlEvent::End(name) => {
                    return Err(XmlError::Extension(format!("unexpected </{name}> in <{}>", Self::LOCAL_NAME)));
                }
                XmlEvent::Text(text) if text.trim().is_empty() => {}
                XmlEvent::Text(_) => {
                    return Err(XmlError::Extension(format!("text is not allowed directly under <{}>", Self::LOCAL_NAME)));
                }
                XmlEvent::Eof => {
                    return Err(XmlError::Extension(format!("unexpected EOF in <{}>", Self::LOCAL_NAME)));
                }
            }
        }
    }
}
