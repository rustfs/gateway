# Contributing to RustFS Gateway

Thanks for considering a contribution. This project is pre-alpha and moves quickly, so please
open an issue describing what you intend to do before writing a large change — it is much
cheaper to redirect a plan than a finished pull request.

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go
through [SECURITY.md](SECURITY.md), never through a public issue or pull request.

## License of contributions

There is no contributor license agreement and nothing to sign. By submitting a contribution you
agree that it is licensed under the [Apache License, Version 2.0](LICENSE), the same license as
the project (section 5 of the license: inbound equals outbound), unless you explicitly state
otherwise in the pull request. Do not submit code you are not entitled to license that way; the
rule on code taken from s3s below is one instance of it.

## The s3s rule: copy knowledge, never code

RustFS Gateway is an independent implementation and must remain provably free of code taken from
[s3s](https://github.com/Nugine/s3s). Three kinds of material get three different treatments,
and the difference is not negotiable:

| Material | Copyright status | Rule in this repository |
|---|---|---|
| **Source code** — including tests, CI workflows, and helper scripts | Covered by s3s's Apache-2.0 license | **Never copy it.** Not even a function, not even "temporarily". Rewriting is far cheaper than carrying a provenance obligation forever. |
| **Protocol behaviour reported in issues and pull requests** — e.g. "AWS returns an unquoted ETag from `GetObjectAttributes`", "presigned URLs cap out at 7 days" | Facts are not copyrightable; the *prose* stays under its author's copyright | Use the facts freely. Write the conformance case yourself. Record the evidence as a **URL plus your own one-line summary** — never paste issue or PR text into this repository. |
| **Methodology** — how one reads Smithy traits, how a codec generator is structured | Ideas and methods are not copyrightable | Learn from it freely, but write your own generator; do not lift `codegen/` sources. |

Because Apache-2.0 would technically permit copying with attribution, be clear about why we
still refuse: any copied file obliges us to preserve headers, track upstream revisions, and
defend the boundary for the lifetime of the project. Independent implementation costs less.

**Recommended practice:** when implementing an area that s3s also covers, work from the AWS
documentation, the Smithy model, and captured real-world traffic — not from s3s's source. If
you have read s3s source recently for an area you are now implementing, say so in the pull
request so a reviewer can look more carefully.

Pull requests carry an explicit checkbox affirming that no s3s code was copied. Ticking it
falsely is grounds for reverting the change and for removal from the project.

The same rule applies to any other project, including AI-generated code that reproduces an
identifiable upstream implementation. If you port code from anywhere, it must be
license-compatible, carry an in-file attribution comment naming the upstream project and
revision, and be registered in [NOTICE](NOTICE) in the same pull request.

## The clean-room rule: MinIO and Garage server source is off limits

The s3s rule above is about a permissively licensed project we still decline to copy. This one is
harder: **never read MinIO server source when implementing MinIO-compatible behaviour**, and the
same for Garage. `minio/minio` is AGPL-3.0 and archived, and a translation of AGPL logic into Rust
is a derivative work — not "inspiration", and not laundered by a rewrite.

Behavioural **facts** remain free to use: what bytes go on the wire, which status a request gets,
which element a client expects. Derive them from protocol observation, `mc --debug` output, public
API documentation, or this repository's own records under `model/overlays/quirks/`. `minio-go` is
Apache-2.0 and using it as a **client** in a test is unaffected.

A pull request that implements a MinIO-compatible behaviour carries this line in its description:

```text
Clean-room: no minio server source was read; behavior derived from protocol observation only.
```

`scripts/check_no_minio_source.sh` enforces the mechanical half — no AGPL licence text, no comment
claiming a port, no vendored server tree, no dependency edge. The half a script cannot check is
what you read, which is why the affirmation is yours. See [docs/dialects.md](docs/dialects.md).

## Licensing of your contribution

Contributions are accepted under the [Apache License, Version 2.0](LICENSE) only. Unless you
state otherwise explicitly, anything you intentionally submit for inclusion is licensed as
described in the license, without additional terms.

## Workflow

1. Fork the repository and create a branch off `main`. `main` is protected; all changes land
   through pull requests.
2. Keep the change focused. One concern per pull request — an unrelated drive-by fix belongs
   in its own.
3. Before pushing, run:

   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets
   cargo xtask verify
   ```

4. Open the pull request, fill in the template honestly, and link the issue it resolves.
5. Expect review comments on public API shape and on anything touching signature verification
   or parsing; those areas get scrutinised hard on purpose.

### Worktree build storage

Before starting a workspace gate, inventory the worktrees with `git worktree list`. In each
worktree you intend to build or retire, resolve Cargo's actual artifact directory:

```bash
cargo metadata --no-deps --format-version 1 | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
```

Use that absolute path with `du -sh /absolute/artifact/path` and
`df -h /absolute/artifact/path` (use its existing parent if the directory does not exist yet).
Do not assume artifacts live in `./target`: Cargo configuration and `CARGO_TARGET_DIR` can
redirect them, including to a directory shared by several worktrees. Count shared paths once.
The repository has observed 6–20 GiB per worktree and a 31 GiB warm artifact directory; these
are measurements, not fixed space requirements. Leave room for the next build's temporary
linker output and doctests as well as retained artifacts. If headroom is uncertain, run one
workspace gate at a time and recheck free space before the next one.

Reclaim artifacts only from completed, idle worktrees, after coordinating with every user of
the resolved directory. From the selected worktree, preview the exact directory first:

```bash
cargo clean --target-dir /absolute/artifact/path --dry-run
```

Add `--verbose` to the preview to list individual paths. After reviewing the preview, repeat
without `--dry-run` to remove those rebuildable artifacts.
Never clean a directory while another build, test, or mutation run uses it. Keep the warm
directory for active work; do not delete source worktrees, uncommitted changes, the Cargo
registry, or installed toolchains to recover build space. Re-run `df -h` after cleanup.

Keep a separate resolved artifact directory for each worktree. Serializing builds is not enough
to make a shared `CARGO_TARGET_DIR` safe: a worktree with older source timestamps can run another
worktree's compiled code, even with `CARGO_INCREMENTAL=0`. Both switch directions reproduced this
in [#1322](https://github.com/rustfs/gateway/issues/1322); separate target directories ran the
expected code in both directions. Check configuration and environment overrides with the metadata
command above before relying on the default worktree-local `target` directory.

If a run may have reused another worktree's code, rebuild in an isolated target and repeat its
gates. Reclaim the old shared artifacts only after every user is idle, using the preview above.
For subsequent builds, `CARGO_INCREMENTAL=0` avoids accumulating incremental compilation state,
at the cost of slower rebuilds; it does not remove existing state or isolate worktrees. After
cleanup, prepare the cold cache with `cargo xtask bootstrap` before measuring the short
verification loop. Reclamation does not waive any of the four required commands in `AGENTS.md`,
their time budgets, or any tests.

### Recording role reviews

Under one visible `## Role Verdicts` heading in the PR description, record each required
role as a list item. Use either `- simplicity-adversary: path/to/file.rs:123 <concrete finding>`
or `- simplicity-adversary: attacked <specific surfaces> — no break found`. Replace the
placeholders with the actual review evidence. The `- ` list marker is required, and the
`no break found` suffix must end a null report (optional final punctuation is allowed).
Bare approval does not satisfy the gate; role findings remain advisory.

The CI workflow reads the PR body from its triggering event. After correcting the description,
trigger a fresh pull-request event, for example by pushing a follow-up commit. Re-running an
existing workflow reuses its original event payload and will not see the corrected body.

## Commits and pull requests

- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)**:
  `type(scope): summary`, e.g. `fix(rustfs-gateway-sig): reject empty x-amz-date`. Common types:
  `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`, `ci`. Breaking changes are
  marked with `!` after the scope and explained in the body.
- **Pull request titles use the same format and stay within 72 characters.** The title is
  what ends up in the changelog; write it for someone who was not in the discussion.
- **Everything written into the repository is in English** — code, comments, documentation,
  commit messages, pull request titles and bodies, issue text. Conversations with AI tools may
  be in any language; their output must not be.

## Engineering expectations

- MSRV is **1.97.1** and the policy in [docs/msrv.md](docs/msrv.md) is enforced strictly; a pull
  request that raises the MSRV outside a minor release is rejected without discussion.
- `unsafe_code` is forbidden workspace-wide, and `missing_docs` is denied. Every public item
  needs a doc comment.
- New dependencies need justification in the pull request description: what it does, why it
  cannot be written in a few dozen lines, its license, and its MSRV.
- Rings 0 and 1 (`rustfs-gateway*` crates) must never depend on a RustFS crate or on a ring-2
  (`rustfs-gateway-*`) crate. CI enforces this; see the ring table in [README.md](README.md).
- Behaviour changes need a test. Protocol behaviour changes need a conformance case with its
  evidence URL.

## If you are an AI agent

`AGENTS.md` at the repository root is the single source of truth for agent rules. Read it
before making changes; nothing in this document overrides it, and it overrides your defaults.
