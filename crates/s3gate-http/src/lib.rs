//! HTTP wire layer.
//!
//! Responsible for: request acceptance, header/query views, limits, aws-chunked framing.
//! NOT responsible for: deciding the framing mode — that is derived from the signature
//! (`PayloadMode` is frozen in `s3gate-sig`, which is why P2 precedes P3).
//! Upstream: `s3gate-types`, `s3gate-stream`. Downstream: `s3gate-sig`.
#![forbid(unsafe_code)]
