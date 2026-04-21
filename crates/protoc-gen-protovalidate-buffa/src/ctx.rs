//! Code-generation context — threading information that cannot be derived
//! from a single `MessageValidators` in isolation.
//!
//! Currently a stub; expanded in later tasks when cross-message references
//! (message recursion, map-entry resolution) need to share descriptor state.

/// Codegen context passed through the emit phase.
///
/// Reserved for Tasks 9–11 (repeated/map/message recursion). The emit phase
/// for scalars/enums/required/oneof does not need it.
#[derive(Debug, Default)]
pub struct CodeGenContext;
