# Security Policy

RustFS Gateway sits directly on untrusted input: it terminates S3 traffic before anything else in the
system sees it. We treat that position as the product's core responsibility, and we would much
rather hear about a problem from you than from an incident report.

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main`  | Yes |
| Latest `0.x` release | Yes |
| Any older `0.x` release | No — upgrade first |

The project is pre-alpha. There are no long-term support branches; fixes land on `main` and in
the next release.

## Reporting a vulnerability

Report it privately through GitHub: repository → **Security** → **Report a vulnerability**
(`https://github.com/rustfs/gateway/security/advisories/new`), or email **security@rustfs.com**.

**Do not open a public issue, pull request, or discussion for a suspected vulnerability**, and
do not post a proof of concept publicly before the coordinated disclosure window closes.

Please include: an explanation of the issue and why it is a security problem, a minimal
reproduction (a raw HTTP request is ideal), the affected commit or release, and your
assessment of the impact.

### Our commitments

- **First response within 3 business days** of your report.
- An assessment with a severity judgement and a remediation plan once we have reproduced it.
- A **90-day coordinated disclosure window** from first response, after which we publish the
  advisory whether or not a fix has shipped. We will publish earlier by mutual agreement, or
  immediately if the issue is being exploited in the wild.
- Credit in the advisory, unless you prefer to stay anonymous.

## What counts as a vulnerability

The two lists below exist so that we and you agree in advance on what is in play. If your
finding is not obviously on either list, report it anyway and let us decide.

### In scope

- **Signature verification bypass** — any input that gets a request accepted without a valid
  SigV4 or SigV2 signature, or that lets a signature be reused across a different request.
- **Presigned URL constraint bypass** — accepting an expired URL, or ignoring a constraint the
  presigned request was bound to (method, resource, headers, POST-policy conditions).
- **Request smuggling / request injection** — `Content-Length`/`Transfer-Encoding` ambiguity,
  `aws-chunked` boundary confusion, header or trailer injection, or any parse divergence that
  lets one connection's bytes be interpreted as a second request.
- **XML parsing attacks** — entity expansion, nesting depth explosion, decompression or size
  amplification leading to denial of service, or any XML feature that produces an outbound
  request (SSRF).
- **Secret leakage** — credentials, signatures, session tokens, or SSE-C keys appearing in
  logs, traces, metrics, or error responses.
- **Authorization bypass** — reaching data without the `Authorizer` being consulted, including
  derived or secondary resources of an operation (for example a sub-resource or a redirect
  target) that is read without its own authorization check.
- **Panic on untrusted input** — any parser or codec panic that aborts the process. This
  framework promises it does not panic on untrusted input; a reproducible panic is a
  vulnerability, not a bug report.
- **Memory-safety issues** — the workspace sets `unsafe_code = "forbid"`, so any memory-safety
  problem is by definition also a policy violation worth reporting.

### Out of scope

- **Bugs in your own `Authorizer`, `SignatureVerifier`, or storage implementation.** RustFS Gateway
  defines these interfaces and calls them correctly; the decision logic behind them is yours.
- **Plaintext credential exposure caused by not terminating TLS.** Deploying RustFS Gateway without
  TLS is a deployment choice, not a framework defect.
- **A `501 Not Implemented` for an S3 feature documented as unsupported.** Missing coverage is
  tracked as a normal issue.
- **Performance shortfalls**, unless you can construct an amplification attack — a small,
  cheap request that costs the server disproportionately more than it costs you.
- **Vulnerabilities in dependencies whose affected code path RustFS Gateway never reaches.** We will
  still update the dependency, but a security report needs a reachability analysis showing a
  path from an RustFS Gateway entry point to the vulnerable call.
- **Attacks that presuppose local root, an already-compromised host, or leaked long-term
  credentials.** If the attacker already has the keys, signature verification working as
  designed is not a finding.
- Missing hardening headers, scanner output without a demonstrated impact, and social
  engineering of maintainers.

## Safe harbour

We will not pursue or support legal action against anyone who reports in good faith, stays
within the scope above, avoids privacy violations and service degradation, and gives us a
reasonable chance to fix the issue before disclosing it.
