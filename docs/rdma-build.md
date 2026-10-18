# Optional external payload build

The ordinary gateway workspace and its default feature set require no access to
the private transport repository. The `external-payload` feature exposes the
transport-neutral handler and payload interfaces independently:

```sh
cargo check -p rustfs-gateway --features external-payload -j 2
```

The private integration is built with an independent manifest outside the normal
workspace. Optional dependencies still participate in Cargo resolution; keeping
the private dependency in that manifest preserves the ordinary build boundary.

```sh
git submodule update --init vendor/rustfs-ucx
./scripts/build-rdma.sh --release
```

The equivalent Cargo command is:

```sh
source vendor/rustfs-ucx/scripts/build-env.sh
cargo +1.98.1 build --manifest-path rdma/Cargo.toml --features rdma --release -j 2
```

This produces the `rustfs-gateway-rdma` integration library for a host to compose
with the public gateway. Its implementation source comes from the pinned private
submodule. `RUSTFS_RDMA_TOOLCHAIN` selects a compatible installed toolchain and
`CARGO_BUILD_JOBS` selects build parallelism. The ordinary gateway toolchain
configuration remains applicable to its own workspace.

Build and install the matching native dependencies using the pinned private
engine's installation guide. Client and server must advertise compatible
capacity capabilities before either endpoint admits an external transfer.

Without the private checkout, the build helper stops before invoking Cargo and
prints the initialization command. Reading the submodule requires repository
authorization. A normal build does not fetch it.

The public protocol kernel depends only on neutral payload, admission,
verification and cancellation interfaces. It never depends on the integration
library. Ordinary requests retain their existing authentication and dispatch.
Requests carrying the reserved external-payload markers are rejected until a
complete authenticated wire integration is installed; an empty HTTP PUT cannot
silently become a normal zero-byte object.

The pinned private integration implements authenticated S3 HTTPS coordination and
external upload/download data. The host explicitly installs the integration and
supplies its trusted connection and authorization context. The enterprise
repository's optional server composes this integration with RustFS storage.
Functional tests using software
transports establish API and lifecycle behavior; NIC RDMA, DPU compatibility and
performance require validation on the target deployment.
