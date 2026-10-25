# rustfs-gateway-types

Handwritten protocol scalars plus the generated DTO surface. Operation and field shapes are indexed
in `OPERATIONS.md` and `spec/operations/`.

## Select response producer

Since types 0.39, `SelectObjectContentOutput.payload` is an `Option<SelectEventStream>`.
The generated `dto::SelectObjectContentEventStream` union represents one event; the root
`SelectEventStream` owns a live `Send` producer of those events and `SelectEventError` values.
Construction does not poll it, and dropping the response drops the producer. Event ordering,
including when to stop after an End or error event, remains the producer's responsibility.

Migrate empty output literals to `SelectObjectContentOutput::default()` or set `payload`
explicitly. The output no longer implements `Clone`; move the response and its producer.
The codec retains absent details and counters, resolved error messages, and the producer's
wire event order. It adds no Content-Type header. The existing preframed response API remains
available to backends that already encode their own frames.

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
