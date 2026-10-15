# rustfs-gateway-rdma

This independent package compiles the private gateway integration from the
pinned `vendor/rustfs-ucx` submodule. The ordinary workspace excludes this
package and does not resolve its private dependency.

| Path | Responsibility | Read when |
| --- | --- | --- |
| `Cargo.toml` | Explicit `rdma` feature and public port dependencies | Changing build selection or dependencies |
| `../vendor/rustfs-ucx/integrations/gateway/src/lib.rs` | Private integration entry point | Connecting prepared transfers to facade ports |
| `../scripts/build-rdma.sh` | Private-source preflight and opt-in Cargo build | Diagnosing source access or build arguments |
| `../docs/rdma-build.md` | Access requirements, build commands and capability limits | Enabling or composing the integration |

The integration depends on the gateway facade's neutral `external-payload`
interfaces and the private transport. The protocol kernel does not depend on
this package. A RustFS host composes the resulting library explicitly.

Build with `../scripts/build-rdma.sh` from this directory or use the documented
manifest command. Run integration tests with
`cargo +1.98.1 test --manifest-path rdma/Cargo.toml --features rdma -j 2` from the
repository root. Native execution and the authenticated external wire path
remain unavailable until their implementations are connected.
