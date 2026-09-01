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

//! Secret-bearing protocol scalar contracts.
//!
//! Responsible for: proving that a decoded SSE-C customer key cannot use ordinary output,
//! comparison, copying, or serialization traits, and that its storage is cleared on drop.
//! NOT responsible for: validating the key's base64 spelling, digest, or transport security.
//! Upstream: generated operation DTOs. Downstream: operation handlers at an explicit exposure
//! boundary.
//!
//! The real `PutObject` field must not be clonable.
//!
//! ```compile_fail
//! use rustfs_gateway_types::ops::put_object;
//!
//! let key = put_object::Input::default().sse_customer_key.unwrap();
//! let _copy = key.clone();
//! ```
//!
//! It must not implement `Debug` or `Display`.
//!
//! ```compile_fail
//! use rustfs_gateway_types::ops::put_object;
//!
//! let key = put_object::Input::default().sse_customer_key.unwrap();
//! let _ = format!("{key:?}");
//! ```
//!
//! ```compile_fail
//! use rustfs_gateway_types::ops::put_object;
//!
//! let key = put_object::Input::default().sse_customer_key.unwrap();
//! let _ = format!("{key}");
//! ```
//!
//! It must not implement equality or serialization traits.
//!
//! ```compile_fail
//! use rustfs_gateway_types::ops::put_object;
//!
//! let key = put_object::Input::default().sse_customer_key.unwrap();
//! let _ = key == key;
//! ```
//!
//! ```compile_fail
//! use rustfs_gateway_types::ops::put_object;
//!
//! let key = put_object::Input::default().sse_customer_key.unwrap();
//! let _ = serde_json::to_string(&key);
//! ```
//!
//! Its concrete carrier must promise drop-time zeroization.
//!
//! ```
//! use rustfs_gateway_types::{SseCustomerKey, ops::put_object};
//! use zeroize::ZeroizeOnDrop;
//!
//! fn assert_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}
//!
//! let input = put_object::Input {
//!     sse_customer_key: Some(SseCustomerKey::new("c2VjcmV0".to_owned())),
//!     ..Default::default()
//! };
//! let key = input.sse_customer_key.unwrap();
//! assert_zeroize_on_drop(&key);
//! assert!(key.expose_secret().len() > 1);
//! ```

use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An SSE-C customer-key header value whose backing allocation is cleared on drop.
///
/// The type intentionally implements none of `Clone`, `Debug`, `Display`, `PartialEq`, `Deref`,
/// `AsRef`, or serialization traits. Protocol codecs construct it directly from the wire, and a
/// handler must opt into the narrow [`Self::expose_secret`] boundary before passing the value to
/// its encryption implementation.
pub struct SseCustomerKey {
    value: Zeroizing<String>,
}

impl SseCustomerKey {
    /// Takes ownership of a customer-key header value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    /// Copies a decoded wire view into zeroizing owned storage.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        Self::new(value.to_owned())
    }

    /// Exposes the secret only at the caller's explicit use boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.value.as_str()
    }
}

impl ZeroizeOnDrop for SseCustomerKey {}
