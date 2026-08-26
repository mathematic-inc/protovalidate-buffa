# protovalidate-buffa

Static-codegen [protovalidate] for the [buffa] Rust protobuf runtime.

Annotate your `.proto` messages with `(buf.validate.*)` rules; a codegen plugin
emits pure-Rust `impl Validate` blocks per message. Handlers call
`req.validate()?` at entry (or use the `#[connect_impl]` macro to do it
automatically on every handler in a service impl).

For what the rules *mean*, the full rule catalogue, CEL semantics, and design docs,
read the upstream project. This crate intentionally does not duplicate that
material:

- **Docs:** <https://protovalidate.com/>
- **Rule catalogue:** <https://protovalidate.com/schemas/standard-rules/>
- **Custom rules:** <https://protovalidate.com/schemas/custom-rules/>
- **Predefined rules:** <https://protovalidate.com/schemas/predefined-rules/>
- **Source of truth (`validate.proto`):** <https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto>

[protovalidate]: https://github.com/bufbuild/protovalidate
[buffa]: https://github.com/anthropics/buffa

## Status

**Conformance: 2872 / 2872 (100%)** against the upstream
[`protovalidate-conformance`] harness, covering proto2, proto3, and editions 2023.

## Why a different crate?

Existing Rust implementations of protovalidate (`prost-protovalidate`,
`protocheck`, `protify`) all target [prost]. buffa has a different runtime model:
two-tier owned/borrowed types with zero-copy views, and static generated types
rather than descriptor-driven dynamic messages. Prost-based validators are
incompatible. This repo fills that gap.

Compared to reflection-based implementations, the codegen approach has two characteristics:

- **No runtime descriptor lookup.** Every `validate()` is a direct struct field
  walk that LLVM can inline.
- **Schema-aware compile errors.** Rule / field type mismatches, malformed
  `message.oneof` specs, and CEL expressions that reference non-existent fields
  surface at codegen time rather than at the first call.

[prost]: https://github.com/tokio-rs/prost

## Crates

| Crate | Purpose |
|-------|---------|
| [`protovalidate-buffa`](crates/protovalidate-buffa/) | Runtime library: `Validate` trait, structured `ValidationError` (with typed `compile_error` / `runtime_error` slots), `Violation` / `FieldPath`, rule helpers, `CelScalar` widening trait + Duration/Timestamp helpers, Connect error adapter. CEL rules are transpiled to native Rust at codegen time, so the runtime carries no interpreter. |
| [`protovalidate-buffa-macros`](crates/protovalidate-buffa-macros/) | `#[connect_impl]` attribute macro — inserts request validation at the top of every handler in a service `impl` block. Re-exported from the runtime crate. |
| [`protoc-gen-protovalidate-buffa`](crates/protoc-gen-protovalidate-buffa/) | Codegen plugin. Reads `(buf.validate.*)` extensions off descriptors via buffa's `ExtensionSet`, emits `impl Validate for Foo` blocks. Wire into `buf.gen.yaml`. |
| [`protovalidate-buffa-protos`](crates/protovalidate-buffa-protos/) | Compiled Rust for `buf/validate/validate.proto` (vendored under `proto/`). Consumed by the codegen plugin. |

`protovalidate-buffa-conformance` also lives in this workspace but is private
(`publish = false`). See [its README] for the conformance test-run flow.

## Compatibility

This workspace currently targets **buffa 0.9.1**, **connectrpc 0.9**, and
**Rust 1.88+** (edition 2024).

The emitted validators reference buffa's generated-code shape directly (field
placement, map and view types), so the plugin and your `buffa-build` output must
agree on the buffa minor version. buffa is pre-1.0 and treats **minor bumps as
breaking**, so upgrading buffa generally means upgrading this crate in lockstep.

The `connect` feature links `connectrpc`, which itself depends on buffa `^0.9.1`.
The buffa version here must stay in step with connectrpc's. Otherwise, two
incompatible buffa versions get linked and the default `connect` feature breaks
for downstream handlers.

## Supported rules

Every rule family in the upstream [standard-rules catalogue] plus [predefined
rules] is implemented. That is what the 2872 / 2872 conformance number above
measures. See the upstream docs for semantics; this repo does not maintain a
parallel list.

## Quick start

For the proto-annotation side (which rules exist, how to combine them, CEL syntax),
follow the upstream [protovalidate quick start]. The Rust-specific bits are:

```bash
# Install the plugin
cargo install --git https://github.com/mathematic-inc/protovalidate-buffa protoc-gen-protovalidate-buffa
```

Add to your `buf.gen.yaml`:

```yaml
- local: protoc-gen-protovalidate-buffa
  out: gen/protovalidate
  strategy: all
```

Annotate a proto (see upstream for the full rule vocabulary):

```protobuf
syntax = "proto3";
import "buf/validate/validate.proto";

message CreateUserRequest {
  string email = 1 [(buf.validate.field).string = {
    min_len: 5,
    max_len: 254,
    email: true
  }];
  int32 age = 3 [(buf.validate.field).int32 = { gte: 13, lte: 150 }];
}
```

Use in a Connect handler:

```rust
use protovalidate_buffa::Validate;

#[protovalidate_buffa::connect_impl]
impl UserService for UserServiceImpl {
    async fn create_user(
        &self,
        ctx: Context,
        request: connectrpc::ServiceRequest<'_, pb::CreateUserRequest>,
    ) -> Result<(pb::CreateUserResponse, Context), ConnectError> {
        // #[connect_impl] validates the request here automatically.
        // Body only sees already-validated requests.
    }
}
```

## Error model

`Validate::validate` returns `Result<(), ValidationError>`:

```rust
pub struct ValidationError {
    pub violations: Vec<Violation>,
    // Schema mismatch detected at codegen time.
    pub compile_error: Option<String>,
    // Rule precondition failed, e.g. non-UTF-8 bytes under `pattern`.
    pub runtime_error: Option<String>,
}
```

Match on the typed fields rather than stringly-typed rule-id prefixes. `Violation`
and `FieldPath` mirror the [upstream proto shape]; see those message definitions
for field semantics. The `connect` feature provides
`ValidationError::into_connect_error` mapping to `InvalidArgument`.

## Conformance testing

See the [conformance README] for how to build the dispatch binary and drive the
upstream harness locally. CI runs
`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` on every push; conformance is currently a local-only /
pre-release check.

## Contributing

Please [start a Discussion] before proposing a change. If we accept the proposal,
a Mathematic maintainer or AI agent will implement it and open a pull request. We
will link the implementation pull request to the Discussion and credit the
proposal's original author. GitHub restricts pull request creation to Mathematic
maintainers and repository collaborators with write, maintain, or admin access,
plus authorized maintenance agents. See [CONTRIBUTING.md] for the full process.

## License

Dual-licensed under Apache-2.0 or MIT at your option.

[`protovalidate-conformance`]: https://github.com/bufbuild/protovalidate/tree/main/tools/protovalidate-conformance
[CONTRIBUTING.md]: CONTRIBUTING.md
[conformance README]: crates/protovalidate-buffa-conformance/README.md
[its README]: crates/protovalidate-buffa-conformance/README.md
[predefined rules]: https://protovalidate.com/schemas/predefined-rules/
[protovalidate quick start]: https://protovalidate.com/quickstart/
[standard-rules catalogue]: https://protovalidate.com/schemas/standard-rules/
[start a Discussion]: https://github.com/mathematic-inc/protovalidate-buffa/discussions/new
[upstream proto shape]: https://github.com/bufbuild/protovalidate/blob/main/proto/protovalidate/buf/validate/validate.proto
