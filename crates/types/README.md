# rustfs-gateway-types

Handwritten protocol scalars plus the generated DTO surface. Operation and field shapes are indexed
in `OPERATIONS.md` and `spec/operations/`.

## Tag field presence

Since types 0.38, `Tag.key` and `Tag.value` are `Option<String>`. Historical Tagging,
Lifecycle and Replication records can omit either member. `None` preserves that absence;
`Some(String::new())` preserves a present empty element. Persistence bridges, XML output
and legacy conversions retain the distinction. The default Tree request reading requires both
members. The RustFs reading preserves absent members for the host's original validation.
The model's requiredness is separate from the owned storage representation.

Callers migrating from `String` wrap present values in `Some` and explicitly reject absence
when they require a complete pair. Do not use `unwrap_or_default` to invent a value for an
absent member. `TaggingBridgeError::MissingRequiredMember` remains available for source
compatibility, but missing Tag fields no longer cause it.
