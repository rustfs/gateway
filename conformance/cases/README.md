# Writing a conformance case

Read [`../README.md`](../README.md) first for the freeze policy and the conventions. This file is
the recipe for adding the next case. Everything here is checkable by
`cargo xtask conformance validate`.

## Procedure

1. **Find the behavioural fact and its source.** A case starts from something observed — an upstream
   issue, an AWS API page, an RFC clause, a capture from a real client — not from a guess about what
   would be reasonable. If you cannot produce a URL, you do not yet have a case.

2. **Pick the domain and the number.** The domain is the directory: `etag`, `sig`, `chunked`, `cond`,
   `list`, `mpu`, and so on. Create a new directory when no existing one fits. The id is
   `c-<domain>-<NNNN>` with the next unused number in that domain, and the file must be named
   `<id>.toml`. Numbers are never reused.

3. **Write `rationale` before writing any assertion.** Say what breaks in the real world when this
   behaviour is wrong, and how the failure would look to a client. If the rationale reduces to "the
   spec says so", the case is probably asserting an implementation detail. This field is mandatory
   and the runner refuses to load a case without it: an unexplained case is one nobody will dare to
   change or delete, and it will outlive its usefulness by years.

4. **Record `evidence`.** One URL plus one original sentence each. Never paste upstream prose — see
   the compliance note in the parent README.

5. **Decide `polarity` honestly.** `negative` means the input is hostile or malformed and the case
   asserts refusal, error shape, or safe termination. The corpus requires negative cases to outnumber
   positive ones, and the way that requirement gets quietly broken is by labelling a happy-path case
   negative because it expects an error.

6. **Choose the strongest expectation the behaviour permits.** In order of preference:
   `body.exact_utf8` or `body.golden` (bytes), then `body.xml` plus `contains_utf8`, then status and
   error code alone. A status-only assertion is acceptable only when the body is genuinely
   unconstrained, and the rationale should say why. Add `headers_absent` whenever the absence of a
   header is part of correctness — a failure response that carries an `ETag` is a failure response
   that wrote something.

7. **Reach for the time-domain fields when the failure is a hang or a buffer.** `delay_ms` on chunks,
   a control chunk, `expect.timing.terminate_within_ms`,
   `expect.request_progress.body_bytes_sent_at_response`. These exist because the worst bugs in this
   area produce no wrong bytes at all; they produce bytes at the wrong time, or none ever.

8. **Pin the clock if the response contains one.** Any body with `LastModified`, `Expires`, or a
   date-bearing header needs `[clock] fixed` before it can be compared byte for byte.

9. **List the quirks.** Every quirk in `model/overlays/` whose flip this case would notice, not only the
   one that motivated it. The mutation gate builds its coverage matrix by inverting this field.

10. **Validate, then run.**

    ```bash
    cargo xtask conformance validate
    cargo xtask conformance run --filter '<domain>/'
    ```

    A new case that fails because the behaviour is not implemented yet is still committed. Red for a
    stated reason beats absent.

## Worked examples in this directory

Each of these was written to exercise a different part of the schema; read the one closest to your
case before starting.

| Case | Shows how to |
|---|---|
| `etag/c-etag-0001.toml` | Pin both sides of an exception in one case; reuse a connection across exchanges; use clock injection to make a body comparable |
| `chunked/c-chunked-0001.toml` | Pace chunks, terminate a request abnormally, and assert that the server answers rather than hangs |
| `cond/c-cond-0001.toml` | The simple single-exchange form; a byte-exact error document; header absence as proof that a write did not happen |
| `list/c-list-0001.toml` | Golden files, redaction of a server-minted token, capturing a value from one response and signing it into the next |
| `sig/c-sig-0001.toml` | Sign correctly and tamper with exactly one canonical component; assert that refusal preceded the payload |
| `mpu/c-mpu-0001.toml` | A failure delivered inside a 200 response: `kind = "stream_error"` with `body_bytes_before_error` |

## Things that will get a case rejected in review

- A `rationale` that restates the assertion instead of explaining the consequence.
- Evidence that is a search result, a chat log, or a link that will not resolve in two years.
- A hand-written signature, hash, or chunk framing where `sign.mode` would have computed it.
- `redact` used on an element whose value is actually deterministic — that is an assertion quietly
  deleted.
- A case that asserts only a status code when the response body is fully determined.
- A new field. The schema is frozen; see the change procedure in the parent README.
