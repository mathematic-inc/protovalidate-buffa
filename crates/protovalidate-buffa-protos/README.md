# protovalidate-buffa-protos

Canonical Buffa types for the vendored `buf/validate/validate.proto` schema,
including `buf.validate.Violations`. [`protoc-gen-protovalidate-buffa`] uses the
annotation types; [`protovalidate-buffa`] re-exports the module as `proto` for
structured validation errors and diagnostic conversion.

Generated Rust is checked in under `src/generated/`. Normal downstream builds
require neither protoc nor a code-generation build script. Imported well-known
types use `buffa-types` and `buffa-descriptor`, so consumers share those types.

The default `views` feature preserves the existing generated view API. Disabling
default features omits views; owned messages remain available. The optional
`json` feature enables canonical protobuf JSON serialization and deserialization,
including `buffa::json_helpers::ProtoJson`. Transport error details use protobuf
bytes and do not require this feature.

## Regeneration

Only maintainers regenerating sources need protoc and its well-known includes.
From the workspace root:

```sh
PROTOC="$(mise which protoc)" mise exec -- cargo run --locked \
  -p protovalidate-buffa-protos --example regenerate
```

This runs the existing `buffa-build` generator, pinned to 0.9.2 in dev-dependencies,
with explicit source output, sibling-relative includes, and generated feature
gates. `Cargo.lock` pins its transitive dependencies; `mise.toml` pins protoc.
Commit the entire generated directory when changing the schema or generator.
Running the command again without input changes must reproduce identical files.

```sh
mise exec -- cargo test -p protovalidate-buffa --all-features --locked
mise exec -- cargo package --list --locked -p protovalidate-buffa-protos
```

[`protoc-gen-protovalidate-buffa`]: ../protoc-gen-protovalidate-buffa/
[`protovalidate-buffa`]: ../protovalidate-buffa/
