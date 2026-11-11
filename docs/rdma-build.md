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

The private source is not a git submodule. Cargo initialises every submodule of
a git dependency when it checks this repository out, so a submodule that a
consumer cannot fetch makes the whole repository unusable as a dependency for
them (rustfs/gateway#1591). Instead, `rdma/rustfs-ucx.rev` records the private
repository's URL and the exact commit this integration is built against, and
`vendor/rustfs-ucx/` is ignored by git. From the repository root, with an
account that can read the private repository:

```sh
git clone git@github.com:rustfs/rustfs-ucx.git vendor/rustfs-ucx
git -C vendor/rustfs-ucx checkout --detach "$(sed -n 's/^rev = //p' rdma/rustfs-ucx.rev)"
./scripts/build-rdma.sh --release
```

An existing checkout moves to a new pin with
`git -C vendor/rustfs-ucx fetch origin` followed by the same `checkout --detach`.
To change the pin, edit the `rev = ` line of `rdma/rustfs-ucx.rev` to the full
40-character commit id; it is reviewed like any other change.

The equivalent Cargo command is:

```sh
source vendor/rustfs-ucx/scripts/build-env.sh
cargo +1.98.1 build --manifest-path rdma/Cargo.toml --features rdma --release -j 2
```

This produces the `rustfs-gateway-rdma` integration library for a host to compose
with the public gateway. Its implementation source comes from the private
checkout at the pinned commit. `RUSTFS_RDMA_TOOLCHAIN` selects a compatible installed toolchain and
`CARGO_BUILD_JOBS` selects build parallelism. The ordinary gateway toolchain
configuration remains applicable to its own workspace.

Build and install the matching native dependencies using the pinned private
engine's installation guide. Client and server must advertise compatible
capacity capabilities before either endpoint admits an external transfer.

The build helper never fetches the private source itself: reaching a private
remote would prompt for credentials or touch the network whenever someone only
meant to compile. It stops before invoking Cargo, with exit status 2, when:

- `rdma/rustfs-ucx.rev` is missing or malformed (no `url = `, or a `rev = ` that
  is not one full 40-character lowercase commit id);
- `vendor/rustfs-ucx` is missing or empty, printing the clone and checkout
  command for the pinned commit;
- `vendor/rustfs-ucx` is not a git checkout of its own;
- the checkout's `HEAD` is not the pinned commit, naming both commits;
- the checkout lacks `Cargo.toml`, `integrations/gateway/src/lib.rs` or
  `scripts/build-env.sh`.

Reading the private repository requires authorization. A normal build does not
fetch it, and `scripts/check_no_git_submodules.sh` keeps submodules out of this
repository.

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
