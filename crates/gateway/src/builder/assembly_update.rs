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

//! The limited builder for replacing live request settings and middleware together.
//!
//! Responsible for: exposing only fields that participate in an atomic assembly update while
//! reusing service-builder registration. NOT responsible for: host authentication, security
//! floors, admission, or publication. Upstream: service owners. Downstream: `S3Service`.

use std::sync::Arc;

use rustfs_gateway_core::Dialect;

use crate::config::AssemblySnapshot;
use crate::routing::RuntimeAssembly;
use crate::{
    Authorizer, AuthzAuditSink, Handler, Observer, OpLayer, Operation, OperationCodec, PolicySource, PolicyTimeout,
    ServiceBuilder, ServiceConfig, StageFilter,
};

/// A complete replacement of the service's mutable request assembly.
///
/// Used by [`crate::S3Service::replace_assembly`]. Registration and validation use the same builder
/// as initial service assembly. Every update supplies the complete registry and authorizer;
/// omitted filters, layers, and observers become their empty defaults.
///
/// The type exposes no authenticator, security-floor, governor, listener, or other fixed host
/// settings, so an attempted host update cannot be accepted and silently ignored.
#[derive(Debug, Default)]
pub struct AssemblyUpdate {
    builder: ServiceBuilder,
}

impl AssemblyUpdate {
    /// Starts an update with default request settings and no registered operations or authorizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the request-body and deadline settings for the new assembly.
    #[must_use]
    pub fn config(mut self, config: ServiceConfig) -> Self {
        self.builder = self.builder.config(config).0;
        self
    }

    /// Registers one operation and its codec and handler using the initial assembly rules.
    #[must_use]
    pub fn register<O, B>(mut self, backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        self.builder = self.builder.register::<O, B>(backend);
        self
    }

    /// Installs the route rows from one validated dialect declaration.
    #[must_use]
    pub fn dialect(mut self, dialect: &Dialect) -> Self {
        self.builder = self.builder.dialect(dialect);
        self
    }

    /// Adds a stage filter in registration order.
    #[must_use]
    pub fn stage_filter(mut self, filter: impl StageFilter) -> Self {
        self.builder = self.builder.stage_filter(filter);
        self
    }

    /// Adds a layer around one registered operation, in outer-to-inner order.
    #[must_use]
    pub fn op_layer<O, L>(mut self, layer: L) -> Self
    where
        O: Operation,
        L: OpLayer<O>,
    {
        self.builder = self.builder.op_layer::<O, L>(layer);
        self
    }

    /// Installs the required authorizer for both authorization stages.
    #[must_use]
    pub fn authorizer(mut self, authorizer: impl Authorizer) -> Self {
        self.builder = self.builder.authorizer(authorizer);
        self
    }

    /// Installs the source read once before this generation's authorization stages.
    #[must_use]
    pub fn policy_source(mut self, source: impl PolicySource) -> Self {
        self.builder = self.builder.policy_source(source);
        self
    }

    /// Sets the validated hard limit for the request's policy read.
    #[must_use]
    pub fn policy_timeout(mut self, timeout: PolicyTimeout) -> Self {
        self.builder = self.builder.policy_timeout(timeout);
        self
    }

    /// Installs the read-only sink for this generation's authorization decisions.
    #[must_use]
    pub fn authz_audit(mut self, sink: impl AuthzAuditSink) -> Self {
        self.builder = self.builder.authz_audit(sink);
        self
    }

    /// Installs the read-only observer for ordinary and committed request outcomes.
    #[must_use]
    pub fn observer(mut self, observer: impl Observer) -> Self {
        self.builder = self.builder.observer(observer);
        self
    }

    pub(crate) fn into_snapshot(self) -> Result<AssemblySnapshot, crate::AssemblyError> {
        let builder = self.builder;
        let authorizer = builder.validate_assembly()?;
        let routing = super::assemble_routing(builder.router, builder.pending, builder.op_layers)?;
        if builder.dangerous_allow_all_authorizer {
            crate::logging::allow_all_authorizer_assembled();
        }
        let config = Arc::clone(&builder.config.load_full().config);
        Ok(AssemblySnapshot {
            config,
            runtime: Some(Arc::new(RuntimeAssembly {
                routing: Arc::new(routing),
                filters: Arc::from(builder.filters),
                authorizer,
                policy_source: builder.policy_source,
                policy_timeout: builder.policy_timeout,
                authz_audit: builder.authz_audit,
                observer: builder.observer,
            })),
        })
    }
}

impl ServiceBuilder {
    pub(super) fn validate_assembly(&self) -> Result<Arc<dyn Authorizer>, crate::AssemblyError> {
        if self.pending.is_empty() {
            return Err(crate::AssemblyError::EmptyRegistry {
                rule: crate::RuleRef::EMPTY_REGISTRY,
            });
        }
        self.authorizer
            .as_ref()
            .cloned()
            .ok_or(crate::AssemblyError::MissingAuthorizer {
                rule: crate::RuleRef::MISSING_AUTHORIZER,
            })
    }
}
