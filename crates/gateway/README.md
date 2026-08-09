# rustfs-gateway

The public facade that assembles the protocol kernel into a Tower/Hyper service.

Assembly refusals carry stable rule identifiers:

```rust
use rustfs_gateway::RuleRef;

assert_eq!(RuleRef::MISSING_AUTHORIZER.as_str(), "asm-missing-authorizer");
```
