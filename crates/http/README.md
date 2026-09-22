# rustfs-gateway-http

Bounded HTTP request-head and body ingestion. Signature verification chooses the payload mode
before this crate decodes aws-chunked framing.

## Read-only transport values

An accepted request exposes typed transport values through a read-only view. Cloning the view
retains the same values; it does not grant mutation access to the extension bag.

```no_run
use rustfs_gateway_http::TransportExtensions;
fn inspect(values: &TransportExtensions) -> Option<&usize> {
    values.get::<usize>()
}
```

The view cannot insert, remove, or mutably look up a bag entry, even when owned:

```compile_fail,E0599
use rustfs_gateway_http::TransportExtensions;
fn insert(mut values: TransportExtensions) {
    values.insert(17_usize);
}
```

```compile_fail,E0599
use rustfs_gateway_http::TransportExtensions;
fn remove(mut values: TransportExtensions) {
    values.remove::<usize>();
}
```

```compile_fail,E0599
use rustfs_gateway_http::TransportExtensions;
fn mutate(mut values: TransportExtensions) {
    values.get_mut::<usize>();
}
```

A successful lookup returns a shared reference, not mutable access:

```compile_fail,E0308
use rustfs_gateway_http::TransportExtensions;
fn mutate(values: &TransportExtensions) {
    let _: Option<&mut usize> = values.get::<usize>();
}
```
