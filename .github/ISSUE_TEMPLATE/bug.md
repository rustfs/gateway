---
name: Bug report
about: A defect in the gateway framework itself
title: "[bug] "
labels: bug
---

> **Do NOT use this template for a suspected security vulnerability.**
> Report those privately through a GitHub Security Advisory:
> https://github.com/rustfs/gateway/security/advisories/new — see `SECURITY.md`.
>
> If gateway behaves differently from real AWS S3 on the wire, use the
> **Protocol mismatch** template instead: it requires wire evidence.

## Minimal reproduction (mandatory)

<!-- Runnable code or a curl / aws-cli invocation. "It sometimes fails under
     load" is not a reproduction. Reduce it until nothing can be removed. -->

```bash
```

## Expected vs actual

- **Expected**:
- **Actual**:

## Panic?

- [ ] This is a panic. If so, paste the full backtrace captured with
      `RUST_BACKTRACE=1`:

```console
```

## Versions

- gateway version / commit:
- `rustc -vV` output:

```console
$ rustc -vV
```

- OS and architecture:

## Anything else

<!-- Frequency, whether it is a regression and which version last worked. -->
