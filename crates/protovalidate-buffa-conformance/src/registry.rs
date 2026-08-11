//! Dispatch table from proto fully-qualified name to a parse+validate
//! function. The `dispatch_known` / `dispatch_known_view` functions are
//! generated at build time from the set of compiled cases protos.

use crate::pb_validate;

pub enum CaseOutcome {
    Valid,
    Invalid(pb_validate::Violations),
    RuntimeError(String),
    CompilationError(String),
    Unsupported,
}

#[expect(
    clippy::too_many_lines,
    clippy::redundant_pub_crate,
    reason = "generated dispatch table: one match arm per registered message type"
)]
mod dispatch_impl {
    use super::CaseOutcome;
    include!(concat!(env!("OUT_DIR"), "/dispatch.rs"));
}
use dispatch_impl::{dispatch_known, dispatch_known_view};

/// Validate `bytes` as `fqn` through both of buffa's representations and
/// return the verdict.
///
/// Every case is validated twice — once against the owned message, once
/// against the borrowed view — and the two verdicts must match. A divergence
/// is reported as a failure in its own right, so the suite measures
/// owned/view agreement on top of spec conformance.
#[must_use]
pub fn dispatch(fqn: &str, bytes: &[u8]) -> CaseOutcome {
    let Some(owned) = dispatch_known(fqn, bytes) else {
        return CaseOutcome::Unsupported;
    };
    // A message in the owned table but not the view one means the two tables
    // drifted apart. Report it rather than passing the case on the owned
    // verdict alone, which would quietly shrink what the run covers.
    let Some(view) = dispatch_known_view(fqn, bytes) else {
        return CaseOutcome::RuntimeError(format!(
            "{fqn} has an owned validator but no view validator — \
             the dispatch tables are out of sync"
        ));
    };
    let (owned_summary, view_summary) = (summarize(&owned), summarize(&view));
    if owned_summary != view_summary {
        return CaseOutcome::RuntimeError(format!(
            "owned/view validation diverged for {fqn}: \
             owned={owned_summary}, view={view_summary}"
        ));
    }
    owned
}

/// Render an outcome to a comparable string. Violations carry no `PartialEq`,
/// so their debug form stands in — it covers field path, rule path, rule id,
/// and the key/value flags that distinguish otherwise-identical violations.
///
/// Violations are compared as a set, not a sequence. Protobuf leaves map
/// iteration order undefined, and the two shapes take it up differently: an
/// owned map walks its hasher's order (which is not even stable between
/// decodes), a view walks wire order. Comparing positions would flag that as a
/// divergence when the verdicts are identical.
fn summarize(outcome: &CaseOutcome) -> String {
    match outcome {
        CaseOutcome::Valid => "valid".to_string(),
        CaseOutcome::Invalid(v) => {
            let mut rendered: Vec<String> = v.violations.iter().map(|x| format!("{x:?}")).collect();
            rendered.sort_unstable();
            format!("invalid([{}])", rendered.join(", "))
        }
        CaseOutcome::RuntimeError(m) => format!("runtime_error({m})"),
        CaseOutcome::CompilationError(m) => format!("compilation_error({m})"),
        CaseOutcome::Unsupported => "unsupported".to_string(),
    }
}
