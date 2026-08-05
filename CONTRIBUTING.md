# Contributing to RustFS Gateway

Thanks for considering a contribution. This project is pre-alpha and moves quickly, so please
open an issue describing what you intend to do before writing a large change — it is much
cheaper to redirect a plan than a finished pull request.

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go
through [SECURITY.md](SECURITY.md), never through a public issue or pull request.

## Contributor License Agreement

Every contributor must sign the RustFS CLA, version 2, before their first pull request can be
merged. The CLA text is at <https://github.com/rustfs/cla/blob/main/cla/v2.md>.

Signing is done by comment: on your pull request, post a comment whose body is exactly

```text
I have read and agree to the CLA.
```

The `CLA Check` status turns green once the signature is recorded in the
[rustfs/cla](https://github.com/rustfs/cla) registry. You only sign once; it covers all your
later contributions across RustFS repositories that use this CLA.

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

## Commits and pull requests

- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)**:
  `type(scope): summary`, e.g. `fix(s3gate-sig): reject empty x-amz-date`. Common types:
  `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`, `ci`. Breaking changes are
  marked with `!` after the scope and explained in the body.
- **Pull request titles use the same format and stay within 72 characters.** The title is
  what ends up in the changelog; write it for someone who was not in the discussion.
- **Everything written into the repository is in English** — code, comments, documentation,
  commit messages, pull request titles and bodies, issue text. Conversations with AI tools may
  be in any language; their output must not be.

## Engineering expectations

- MSRV is **1.89** and the policy in [docs/msrv.md](docs/msrv.md) is enforced strictly; a pull
  request that raises the MSRV outside a minor release is rejected without discussion.
- `unsafe_code` is forbidden workspace-wide, and `missing_docs` is denied. Every public item
  needs a doc comment.
- New dependencies need justification in the pull request description: what it does, why it
  cannot be written in a few dozen lines, its license, and its MSRV.
- Rings 0 and 1 (`s3gate*` crates) must never depend on a RustFS crate or on a ring-2
  (`rustfs-gateway-*`) crate. CI enforces this; see the ring table in [README.md](README.md).
- Behaviour changes need a test. Protocol behaviour changes need a conformance case with its
  evidence URL.

## If you are an AI agent

`AGENTS.md` at the repository root is the single source of truth for agent rules. Read it
before making changes; nothing in this document overrides it, and it overrides your defaults.
