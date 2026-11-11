# rustfs-gateway-rdma

This independent package compiles the private gateway integration from a
`vendor/rustfs-ucx` checkout at the commit pinned in `rustfs-ucx.rev`. The
checkout is not a submodule and is ignored by git (rustfs/gateway#1591). The
ordinary workspace excludes this package and does not resolve its private
dependency.

| Path | Responsibility | Read when |
| --- | --- | --- |
| `Cargo.toml` | Explicit `rdma` feature and public port dependencies | Changing build selection or dependencies |
| `rustfs-ucx.rev` | Private repository URL and the exact commit the build verifies | Fetching the private source or moving the pin |
| `../vendor/rustfs-ucx/integrations/gateway/src/lib.rs` | Private integration entry point | Connecting prepared transfers to facade ports |
| `../scripts/build-rdma.sh` | Pin and private-checkout preflight, then opt-in Cargo build | Diagnosing source access, pin mismatches or build arguments |
| `../docs/rdma-build.md` | Access requirements, build commands and capability limits | Enabling or composing the integration |

The integration depends on the gateway facade's neutral `external-payload`
interfaces and the private transport. The protocol kernel does not depend on
this package. A RustFS host composes the resulting library explicitly.

Fetch the private source from the repository root with
`git clone git@github.com:rustfs/rustfs-ucx.git vendor/rustfs-ucx` and
`git -C vendor/rustfs-ucx checkout --detach <rev from rustfs-ucx.rev>`; the
build helper prints the exact command when the checkout is missing and refuses
any other commit. Build with `../scripts/build-rdma.sh` from this directory or
use the documented manifest command. From the repository root, load
`source vendor/rustfs-ucx/scripts/build-env.sh` before running integration tests with
`cargo +1.98.1 test --manifest-path rdma/Cargo.toml --features rdma -j 2`.
The pinned private implementation provides the connected data and authenticated
external wire path. The host supplies explicit service and storage composition;
see the private documentation for validation requirements.
