# Packaging examples

Both examples generate Buffa types and validators into the same directory.
Handwritten Rust modules include the types and validators together. The
validator plugin's `packaging` and `file_per_package` flags are independent:
the first example disables packaging with per-source output, and the second
also enables per-package output. Buffa uses `file_per_package=true` in both.
The build script uses the workspace's plugin library, so you can try a checkout
without installing a plugin binary.

You need Rust and `protoc` on `PATH`, or set `PROTOC` to its executable. From
the repository root:

```sh
mise install rust protoc
cargo run -p protovalidate-buffa-packaging-examples --bin same_module
cargo run -p protovalidate-buffa-packaging-examples --bin split_package
```

## Per-source validators in one module

[`same_module.rs`](src/bin/same_module.rs) mounts the types and validators for
[`user.proto`](proto/user.proto) inside `mod users`. It accepts a valid email
and rejects an invalid one, using both `User` and `UserView`.
It sets `packaging=false` and leaves `file_per_package=false` at its default.

```rust
mod users {
    include!(concat!(env!("OUT_DIR"), "/example.users.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/user.validate.rs"));
}
```

This package has no cross-package references, so the module can use any name.

## Per-package validators across source files

[`split_package.rs`](src/bin/split_package.rs) mounts `example.orders.v1`,
which contains [`Order`](proto/order.proto) and [`LineItem`](proto/line_item.proto)
in separate source files. It sets `packaging=false,file_per_package=true`.
A single `example.orders.v1.validate.rs` contains both
validators. Adding another message file to that package needs no new include.

`LineItem` references [`Currency`](proto/shared/currency.proto) from
`example.money.v1`. The handwritten modules preserve the package hierarchy so
Buffa's relative paths resolve. It also imports `crate::example` in the orders
module so validators can resolve the enum's `example::money::v1::Currency` path.
The currency
package has no messages and needs no validator file. Source directories do
not mirror package names in these schemas.

The program checks valid orders, invalid quantities, unknown enum values, and
empty orders. It validates owned messages and views and checks the violation
paths for nested line items.

## Generation and tests

[`build.rs`](build.rs) compiles the schemas once and passes the resulting
descriptors to both generators. It uses the repository's existing
`buf/validate/validate.proto`; no schema downloads are needed. Cargo writes
the generated files under `OUT_DIR`.

To use the same layout with `buf generate`, configure the plugin pair as shown
in the [root README](../../README.md#include-validators-beside-message-types).
Keep `strategy: all` so each package's source files reach the plugin in one
request. `proto_module` has no effect when packaging is disabled.

CI runs both examples' behavior tests through `cargo test --workspace
--all-targets`. To run just these tests:

```sh
cargo test -p protovalidate-buffa-packaging-examples
```
