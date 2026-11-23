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

//! Responsible for: installing a typed operation, its handler and its optional decode error mapping.
//! NOT responsible for: deciding registration conflicts or validating the operation input.
//! Upstream: service builder registrations. Downstream: the core router and its dispatch entries.

use std::sync::Arc;

use rustfs_gateway_core::{CodecError, Handler, OperationCodec};

use super::{ErasedOpLayer, ServiceBuilder};
use crate::assembly::{AssemblyError, RuleRef};
use crate::dispatch::OperationDispatch;
use crate::ext::{OpLayer, OpLayerSlot};

impl ServiceBuilder {
    /// Registers `backend` as the handler for one operation.
    ///
    /// The registration goes to `rustfs_gateway_core::RouterBuilder` as well as to this crate's
    /// wire table, so every registration-time refusal — a duplicate, an un-namespaced third-party
    /// name, a name colliding with an AWS one, an operation with no authorisation action — is the
    /// core's answer and not a second implementation of it. Refusals surface from
    /// [`ServiceBuilder::build`].
    #[must_use]
    pub fn register<O, B>(self, backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        self.register_operation::<O, B>(backend, None)
    }

    /// Registers a handler and replaces one exact input-decode refusal on this operation.
    ///
    /// The code, message and member must all match `original`. Invalid input never reaches the
    /// handler. Authentication, handler and encoding errors are unaffected. A replacement outside
    /// the 4xx and 5xx ranges fails closed as an internal error. Requires dynamic dispatch.
    #[must_use]
    pub fn register_with_decode_error_mapping<O, B>(self, backend: Arc<B>, original: CodecError, replacement: CodecError) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        let status = replacement.status();
        let replacement = if status.is_client_error() || status.is_server_error() {
            replacement
        } else {
            CodecError::internal("the configured decode error is not a refusal")
        };
        self.register_operation::<O, B>(backend, Some(Arc::new((original, replacement))))
    }

    fn register_operation<O, B>(mut self, backend: Arc<B>, mapping: Option<Arc<(CodecError, CodecError)>>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        self.has_decode_error_mapping |= mapping.is_some();
        self.router = self.router.handle::<O, B>(Arc::clone(&backend));
        // A taken name is already a `RegistryError::Duplicate` from the line above, which `build`
        // reports. Inserting over it here would leave the two tables disagreeing about which
        // backend answers the operation.
        self.pending.entry(O::NAME).or_insert_with(|| {
            Box::new(move |erased: Vec<ErasedOpLayer>| {
                let mut layers: Vec<Arc<dyn OpLayer<O>>> = Vec::with_capacity(erased.len());
                for slot in erased {
                    // Unreachable through `op_layer`, which keys the slot by the very `O::NAME` the
                    // registration is under. Refused rather than unwrapped: two operation types
                    // sharing one name is an assembly defect, and answering it with a panic would
                    // take a process down at start-up for a reason the message never states.
                    let slot = slot
                        .downcast::<OpLayerSlot<O>>()
                        .map_err(|_| AssemblyError::OpLayerTypeMismatch {
                            operation: O::NAME,
                            rule: RuleRef::OP_LAYER_TYPE,
                        })?;
                    layers.push(slot.into_layer());
                }
                let mut entry = OperationDispatch::layered::<O, B>(backend, layers);
                entry.decode_error_mapping = mapping;
                Ok(entry)
            })
        });
        self
    }
}
