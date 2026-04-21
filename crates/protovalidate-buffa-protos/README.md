# protovalidate-buffa-protos

Compiled Rust types for `buf/validate/validate.proto`, generated via `buffa-build` at build time. Consumed by [`protoc-gen-protovalidate-buffa`](../protoc-gen-protovalidate-buffa/) to read `(buf.validate.*)` options off proto descriptors at codegen time.

The `validate.proto` schema is vendored under `proto/` so this crate is self-contained.

Not intended for direct use — depend on [`protovalidate-buffa`](../protovalidate-buffa/) for the runtime API.
