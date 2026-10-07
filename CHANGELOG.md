# Changelog

## rustfs-gateway-types 0.32.0+aws.2026-10-02

BREAKING: `PostObjectFields` gains `object_lock_legal_hold_status`, `object_lock_mode`,
`object_lock_retain_until_date`, `sse_customer_algorithm`, `sse_customer_key` and
`sse_customer_key_md5`, and no longer implements `Clone` (an `SseCustomerKey` cannot be copied);
`PostObjectInput` gains `content_length`. Migration: a struct literal adds the new members or ends
in `..Default::default()`; code that cloned `PostObjectFields` reads the members it needs instead.
A `PostObject` handler applies the six new members or refuses the upload, as for every other
member it is handed. The model snapshot and storage formats are unchanged.

## rustfs-gateway-types 0.31.0+aws.2026-10-02

The model snapshot moves to AWS api-models-aws commit `7eb6ab98cd5f1e5dc6dd90ea1bdc625f9ae308ba`.
It adds `IntelligentTieringReferenceDate` to the inventory optional-field model; STS is unchanged.
The public `OptionalFields` open string type recognizes the new value. No operation is enabled
by this update, and storage formats are unchanged.
