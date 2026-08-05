---
name: Protocol mismatch
about: gateway behaves differently from real AWS S3 on the wire
title: "[protocol] <Operation>: <one-line difference>"
labels: protocol-mismatch
---

> **A report without the wire evidence in block 3 will be closed immediately.**
>
> Every protocol behaviour in this project must rest on verifiable evidence.
> "I think AWS does not do it that way" is not evidence. Block 3 is mandatory.

## 1. Operation and request shape

- **Operation** (AWS PascalCase name, e.g. `ListObjectsV2`):
- **Method + path shape** (e.g. `GET /{bucket}?list-type=2`):
- **Full set of query keys**:
- **Relevant headers**:

## 2. Expected vs actual

- **Expected** (one sentence):
- **Actual** (one sentence):

## 3. Wire evidence (MANDATORY — provide at least one, both is better)

<!-- REDACTION IS MANDATORY BEFORE PASTING.
     Replace every credential-bearing value with <redacted>, except
     `Authorization`, `x-amz-security-token` and `x-amz-content-sha256`, whose
     *structure* is often the thing under discussion — redact their secret
     material but keep the shape. Never paste a real secret access key.
     An unredacted paste will be edited or the issue closed. -->

**Option A — `aws --debug` output** (must include the request line, all request
headers, the response status, all response headers, and the response body):

```console
$ aws --debug s3api ... 2>&1
```

**Option B — packet capture export** (`.http` file, `tcpdump` or `mitmproxy`
export — redacted the same way):

```http
```

## 4. Reference implementation used for comparison

<!-- Real AWS S3? MinIO? Something else? Their behaviours differ from each
     other, so state exactly what you compared against, and in which region. -->

- [ ] Real AWS S3
- [ ] MinIO (version: )
- [ ] Other (which, and version):

## 5. AWS documentation

- URL:
- **One-sentence summary in your own words**:

<!-- Do NOT paste large excerpts of AWS documentation or of third-party issue
     threads — copyright, see CONTRIBUTING.md. Link plus your own summary. -->

## 6. Environment

- gateway version / commit:
- Client and version (e.g. `aws-cli/2.x`, `boto3 1.x`, `aws-sdk-go-v2`):
- Region used:
- Addressing style: [ ] path-style  [ ] virtual-hosted style
- TLS terminated in front of gateway? [ ] yes  [ ] no
