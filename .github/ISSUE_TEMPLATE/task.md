---
name: Implementation Task
about: Self-contained implementation task (any device / any agent can pick it up)
title: "[gateway][P?-??] "
labels: task
---

> Epic: rustfs/backlog#1677

<!-- HARD RULE FOR THIS TEMPLATE
     An agent that has never seen this repository, on a clean machine, must be
     able to start and self-verify from THIS ISSUE ALONE.
     Therefore: no "as described in the previous issue", no "see the design
     doc" without the content. Copy the relevant conclusions in here.
     Do not delete any of the 13 blocks (0-12). Blocks that do not apply are
     filled with an explicit "N/A because ...". -->

## 0. Metadata

| Field | Value |
|---|---|
| Task ID | `P3-142` |
| Phase | `P3 ...` |
| Risk tier | High (touches signing / auth) · Standard · Mechanical |
| Depends on | `P3-138` (PayloadMode type frozen) |
| Blocks | `P3-150`, `P3-151` |
| Context budget | read 6 files / ~28k tokens / completable in one session |
| Required expert roles | security-adversary, test-adversary (see the trigger table in AGENTS.md) |
| Claim | see the Claim comment on this issue |

## 1. Background and goal (self-contained)

<!-- 200-400 words. What the current state is, why this is needed, and how the
     behaviour of the system differs once it is done.
     MUST be understandable without reading any external document. Copy the
     relevant conclusions in here instead of linking to them. -->

## 2. Required reading

| File | Which part | Why |
|---|---|---|
|  |  |  |

**Do NOT read** (these blow the context budget and teach you nothing):

- `generated/**` — machine-generated, never the source of truth
- `model/s3.json` — 3 MB
- `Cargo.lock`

Need the shape of an operation? Read `OPERATIONS.md`.

## 3. Files touched

- **New**:
- **Modified**:
- **New test cases**:
- **Must NOT be modified**:

## 4. Design (decided — do not redesign)

<!-- A concrete plan, including the rejected alternatives and why they were
     rejected. The implementing agent must not have to make architecture
     choices again. -->

| Rejected alternative | Why rejected |
|---|---|
|  |  |

## 5. Key code skeleton (signature level)

```rust
```

## 6. Protocol evidence

| Source | Link | Key clause (your own summary — do NOT paste the original text) |
|---|---|---|
|  |  |  |

## 7. Full case list (exhaustive, negatives included)

| Case ID | Given / When / Then | Positive / Negative |
|---|---|---|
|  |  |  |

**Requirement: the number of negative cases MUST be >= the number of positive cases.**

<!-- Governance-type tasks may replace this block with an acceptance checklist,
     but every item must be machine-decidable: an exact command plus its
     expected output. -->

## 8. Acceptance criteria (machine-decidable)

- [ ]

## 9. Verification commands (copy-pasteable, with expected output)

```bash
```

## 10. Out of scope (scope fence)

-

## 11. Definition of Done

1. Every box in block 8 is checked;
2. PR title follows Conventional Commits and is <= 72 characters;
3. PR description contains one verdict line per required expert role;
4. This issue has a closing Handoff comment (format below).

## 12. Starting work on a new machine

```bash
git clone https://github.com/rustfs/gateway && cd gateway
rustup show                       # toolchain is pinned by rust-toolchain.toml
cargo xtask bootstrap
git switch -c <phase>/<issue-id>-<slug> origin/main
cargo xtask verify --crate <crate>
```

**Expected cold-start time: <= 5 minutes.** Longer than that means bootstrap
needs work — that is a bug, please open an issue.

<!-- HANDOFF — required before ending a session.
     The carrier of context is this issue, not your local filesystem. Planning
     documents and working notes must never be committed to the repository;
     progress, decisions and traps go into issue comments. This is the only way
     any device / any agent can pick the task up without losing context.
     Append a comment in exactly this shape: -->

    ## Handoff @ <ISO8601 UTC> (device: <id>, branch: <branch> @ <sha>)
    - Done: ...
    - Not done: ...
    - Next command: ...
    - Gotcha: ...
