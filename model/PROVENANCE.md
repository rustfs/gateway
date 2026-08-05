# Vendored AWS Smithy models — provenance

This directory holds the **only** protocol input the gateway's code generation is
allowed to read. Everything downstream — operation shapes, member bindings, XML
names, error shapes — is derived from these two files. If the input can drift,
nothing generated from it is reproducible and the zero-diff codegen gate is
meaningless. This file is the record that makes the input reproducible.

`model/**` is read-only. Nothing in this repository may edit a vendored model in
place; the only legal change is a reviewed bump (see [Bumping](#bumping)).

> **Do not read `model/s3.json` into an editor or an agent context.** It is ~3 MB
> of JSON. Query it programmatically instead:
> `python3 -c "import json;d=json.load(open('model/s3.json'));print(len(d['shapes']))"`

## Pinned upstream

| Field | Value |
|---|---|
| Upstream repository | https://github.com/aws/api-models-aws |
| Upstream branch | main |
| License | Apache-2.0 |
| Upstream copyright line | `Copyright Amazon.com, Inc. or its affiliates.` |
| Pinned commit | `7ca34eee8c313368fd1fad80566fa177ba4a1c0a` |
| Pinned commit date | 2026-08-04 |
| Pin date | 2026-08-05 |
| Upstream has tags or releases | No — `git ls-remote --tags` is empty and the repository has zero releases, so a commit SHA is the only stable identifier |
| Upstream release cadence | Roughly every 2–4 weeks; every commit message is `Release Model Changes:` |
| Last upstream commit touching `models/s3` | `61d7b25d8cc390475a1d3c566f2aef108b9c44af` (2026-07-16) |
| Last upstream commit touching `models/sts` | `87480db7ee4bec827c971dbf0294446591d1b229` (2026-06-02) |
| Semantic diff for this bump | initial pin |

## Vendored files

| Field | Value |
|---|---|
| s3 model path | `models/s3/service/2006-03-01/s3-2006-03-01.json` |
| s3 model file | `model/s3.json` |
| s3 model sha256 | `3d7f95eac05a258236e6edb18525f6706444aa9a73e96789ff23dfea2f57d217` |
| s3 model bytes | 2993923 |
| s3 smithy version | 2.0 |
| s3 service shape | `com.amazonaws.s3#AmazonS3` |
| s3 shape count | 819 |
| s3 operation count | 112 |
| sts model path | `models/sts/service/2011-06-15/sts-2011-06-15.json` |
| sts model file | `model/sts.json` |
| sts model sha256 | `f9af33a09eeb206ab4f63a276f4342c87a23306725be381e2b7ba21ff3e8d40a` |
| sts model bytes | 257699 |
| sts smithy version | 2.0 |
| sts service shape | `com.amazonaws.sts#AWSSecurityTokenServiceV20110615` |
| sts shape count | 110 |
| sts operation count | 11 |

Every number above is re-derived and asserted by `model/tools/verify.py`; the
table is the assertion input, not documentation that can rot.

The S3 service shape carries `aws.api#service`, `aws.auth#sigv4`,
`aws.protocols#restXml` and `smithy.api#xmlNamespace` — the four traits that fix
the wire protocol — plus `smithy.rules#endpointRuleSet`, `endpointBdd` and
`endpointTests`, which are **client-side** endpoint resolution rules and are
ignored everywhere in this repository (a server does not resolve its own
endpoint).

STS is vendored now, unused for the moment, because SigV4 verification needs the
`service=sts` credential-scope dimension and pinning both models in one reviewed
commit is cheaper than pinning them in two.

## Why a commit SHA and not a tag

`aws/api-models-aws` publishes no tags and no releases — verified on 2026-08-05
via `git ls-remote --tags` (empty) and the GitHub releases API (zero entries).
There is no version string to pin to. The alternatives were considered and
rejected:

- **Track `main` unpinned** — generated output stops being reproducible, and the
  zero-diff codegen gate degrades into "whatever AWS shipped this morning".
- **Use `awslabs/aws-sdk-rust/aws-models/*.json`** — a downstream mirror that
  lags the SDK release train. Its own `sync-models.py` prefers the upstream
  `api-models-aws` repository, so consuming the mirror would mean deliberately
  taking staler input. Never use it as the source.
- **Use `smithy-lang/smithy`** — that is the IDL and toolchain, it contains no
  AWS service models.
- **git submodule** — pulls a repository covering 400+ services into every
  clone, blowing the cold-start budget, and a submodule pointer cannot be placed
  under the protected-files review gate the way a vendored file can.

Vendoring is legal here: Apache-2.0 permits redistribution provided the
copyright notice and attribution are retained. The attribution lives in the
repository root `NOTICE`.

## Why the models are vendored verbatim

The files are byte-for-byte what upstream serves at the pinned commit. They are
**not** reformatted, minified, or stripped, because the sha256 in this file is
only meaningful if it can be reproduced by re-downloading from upstream:

```bash
SHA=7ca34eee8c313368fd1fad80566fa177ba4a1c0a
curl -sSL "https://raw.githubusercontent.com/aws/api-models-aws/$SHA/models/s3/service/2006-03-01/s3-2006-03-01.json" \
  | shasum -a 256
```

## Documentation-trait policy

`model/s3.json` carries **1,870** `smithy.api#documentation` traits (306 on
shapes, 1,564 on members), about 570 KB of AWS service prose. The vendored file
keeps them; every consumer strips them:

1. **Drift detection ignores them.** AWS rewrites documentation in nearly every
   release. If prose counted as a change, the weekly drift job would file an
   issue every 2–4 weeks that nobody needs to read, and within a quarter the
   whole signal would be ignored.
2. **Code generation should strip them by default** (owned by the codegen task,
   not this one). The generated crates are a protocol implementation, not a
   redistribution of AWS's documentation site; carrying the prose enlarges the
   artefact and widens the attribution surface for no functional gain.
3. **Agent ergonomics.** Prose is the bulk of the file. Grepping the model for a
   member binding should not return paragraphs of marketing text.

The same reasoning covers `smithy.api#examples` and `smithy.api#externalDocumentation`.

## Integrity check

```bash
python3 model/tools/verify.py
```

The checking logic lives in Python, not in `xtask`, deliberately: the drift
workflow has to run the same comparison against a downloaded candidate, and a
GitHub runner should not build a Rust binary to answer "did anything change".
`cargo xtask model verify` / `cargo xtask model drift` are expected to be thin
wrappers that shell out to these two scripts, added by whoever owns the `xtask`
command surface; the wrappers must not reimplement the logic.

Checks, in order: the pinned commit is 40 hex characters; the upstream
repository field is the official `aws/api-models-aws`; each file's sha256 matches
both its `.sha256` sidecar and this document; byte counts match; each model
parses as Smithy 2.0 JSON AST; the declared service shape exists; shape and
operation counts match. Runs in well under a second and is safe to put in the PR
gate.

Failure modes it is designed to catch: a model edited in place, a sidecar edited
without the model (or the reverse), a `PROVENANCE.md` whose numbers were copied
from a previous pin, and a pin silently redirected to the downstream mirror.

## Drift detection

`.github/workflows/model-drift.yml` runs weekly and on manual dispatch. It
compares the pinned commit against upstream `main`, and when they differ it
downloads the candidate models and runs:

```bash
python3 model/tools/drift.py --against <candidate-dir>
```

which reports only wire-affecting changes: operations added or removed, members
added, removed or changed in optionality or target type, HTTP bindings, XML
names, error shapes, and enum values. Documentation and the client-side endpoint
rule traits are ignored, so a documentation-only upstream release produces an
empty diff and no issue.

**The job never bumps anything.** It opens (or updates) one issue titled
`chore(model): upstream drift detected (<short-sha>)` and stops. It creates no
PR and modifies no file in the repository.

A bot-authored bump PR was considered and rejected: a new required member or a
changed wire name is a protocol event that needs a human decision and possibly
an ADR, and an open PR titled "update model" manufactures the impression that
someone already reviewed it. The job's product is a reviewed decision, not a
merge.

## Bumping

A model bump is its own PR, containing nothing else.

1. Pick the target commit and export it: `SHA=<40 hex>`.
2. Re-download both files at that commit (see the reproduce command above),
   writing them to `model/s3.json` and `model/sts.json`.
3. Regenerate the sidecars:
   `shasum -a 256 model/s3.json | awk '{print $1"  s3.json"}' > model/s3.json.sha256`
   (and the same for `sts`).
4. Update **every** field in the two tables above, including the counts, and
   paste the `drift.py` output into "Semantic diff for this bump".
5. Run `python3 model/tools/verify.py`.
6. In the PR description, state for each breaking entry whether it needs an ADR.

Crate versions carry the model date as build metadata — `X.Y.Z+aws.<model-date>`,
e.g. `0.4.2+aws.2026-08-04`, using the **pinned commit date**, not the pin date.
A bump therefore always produces a version change and its own CHANGELOG section.
Wiring that into `Cargo.toml` belongs to the version-policy task; this file fixes
the rule.
