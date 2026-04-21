//! Plugin internals, exposed as a library so integration tests can import from `scan` and `emit`.
#![expect(
    clippy::too_many_lines,
    reason = "codegen emitters render one Rust file per rule family — splitting the match-per-kind dispatcher into helpers would fragment the per-rule mapping that's meant to be read linearly"
)]
#![expect(
    clippy::match_same_arms,
    reason = "emit dispatch tables intentionally list every FieldKind arm explicitly so new variants trigger a miss at review — merging identical arms hides the exhaustiveness"
)]
#![expect(
    clippy::doc_markdown,
    reason = "proto type names (FieldRules, StringRules, FieldPath, etc.) appear constantly in prose describing the protobuf schema; wrapping each in backticks adds noise without clarifying"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    reason = "FieldDescriptorProto.number and related wire ints are i32 by protobuf schema but semantically non-negative and bounded; casts to usize/u32 are intrinsic to the wire format"
)]

pub mod ctx;
pub mod emit;
pub mod scan;
