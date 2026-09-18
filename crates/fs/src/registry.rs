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

//! The production-registry registration of every reference operation, one method per family.
//!
//! Responsible for: the `register_*` methods on [`FsBackend`] and the per-family entry macros
//! that walk the `reference_operations!` table behind them, so that the operation list, the
//! capability names and what is registered can never disagree.
//! NOT responsible for: the handlers, which live in their family modules, or the table itself,
//! which stays in the crate root beside `capability_names!`.
//! Upstream: `reference_operations!`. Downstream: `compat-sut`'s assembly and the crate's tests.

use std::sync::Arc;

use rustfs_gateway::ServiceBuilder;
// The operation table names its types bare, so every registered type is in scope here.
use rustfs_gateway::dto::*;

use super::FsBackend;

macro_rules! register_crud_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; crud $operation:ty => $name:literal, $($rest:tt)*) => {
        register_crud_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_crud_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_multipart_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; multipart $operation:ty => $name:literal, $($rest:tt)*) => {
        register_multipart_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_multipart_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_versioning_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; versioning $operation:ty => $name:literal, $($rest:tt)*) => {
        register_versioning_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_versioning_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_listing_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; listing $operation:ty => $name:literal, $($rest:tt)*) => {
        register_listing_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_listing_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_acl_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; acl $operation:ty => $name:literal, $($rest:tt)*) => {
        register_acl_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_acl_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_policy_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; policy $operation:ty => $name:literal, $($rest:tt)*) => {
        register_policy_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_policy_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_lifecycle_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; lifecycle $operation:ty => $name:literal, $($rest:tt)*) => {
        register_lifecycle_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_lifecycle_entries!($backend, $builder; $($rest)*)
    };
}

impl FsBackend {
    /// Registers the bucket and object CRUD operations with the production service builder.
    #[must_use]
    pub fn register_crud(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_crud_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the bounded multipart operation family with the production service builder.
    #[must_use]
    pub fn register_multipart(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_multipart_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers bucket versioning and version-aware object operations.
    #[must_use]
    pub fn register_versioning(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_versioning_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the bucket-policy family — the policy, its status and the public-access block —
    /// stored and answered as RustFS stores and answers them (see `policy`).
    #[must_use]
    pub fn register_policy(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_policy_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the four ACL operations, answered as RustFS answers them (see `acl`).
    #[must_use]
    pub fn register_acl(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_acl_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the bounded object listing operation family.
    #[must_use]
    pub fn register_listing(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_listing_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers persistent bucket lifecycle configuration operations and one-shot expiration support.
    #[must_use]
    pub fn register_lifecycle(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_lifecycle_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }
}
