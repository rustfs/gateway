# Protocol hazards

## Copy source authorization is a consuming transition

`CopyObject` and `UploadPartCopy` authorize two different resources: write access to the
destination and read access to the source named by `x-amz-copy-source`. The source is parsed and
normalized once into `CopySourceResources`, then exposed to policy as `s3:GetObject` or
`s3:GetObjectVersion`. The input-stage policy request retains the destination route and the full
source identity: path versus ARN, ARN partition/region/account, access point or outpost, and exact
version ID. That lets a destination policy constrain allowed copy sources without collapsing two
ARNs into one bucket/key pair. Dispatch can receive only `Authorized<O>`, and the handler can reveal
the normalized source only with the exact resource-bound `AuthorizedRead` proof carried by its
request. The route and input stages also receive one `RequestContext`, containing one clock reading
and one opaque policy snapshot.

This prevents three independent failures: a new operation cannot omit `DerivedResources`, the
framework visits every resource in a batch, and the backend does not parse a second source value
after policy has approved the first. `DeleteObjects` follows the same rule: its raw mutable object
list is cleared after derivation, and the backend executes only the proof-gated key/version view.
Runtime coverage is the 16-case `authz/` family, including
source denials, traversal refusals, policy failure, `Indeterminate`, and a policy update between
the two stages; compile-time coverage is under `crates/core/tests/compile_fail/authz_*.rs`.
