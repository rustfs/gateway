# MAP.md format

`MAP.md` is an agent entry point, not an architecture document. It selects the smallest file set
needed to start a task and must stay at or below 100 lines.

Use one three-column table:

| File | Responsibility | Read it when |
|---|---|---|
| `src/example.rs` | One sentence describing what the file owns. | A concrete condition that makes opening it useful. |

Keep responsibilities factual and routing instructions specific. Put design reasoning in an ADR or
module documentation. Never direct readers into `generated/**`, `model/s3.json`, or `Cargo.lock`;
use `OPERATIONS.md`, `spec/operations/`, or `cargo tree -p <crate> -e normal` instead.

The guard is `scripts/check_map_files.sh`.
