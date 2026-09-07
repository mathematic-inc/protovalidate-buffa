//! Regression for cross-package enums in the generator's own module tree.
//!
//! Sloper's default validator root failed with E0603 for RequestOutcome in
//! another package: a private leaf import hid the type from sibling packages.
//! Mount both generated roots directly, with no handwritten package wrappers,
//! and exercise the same fixtures under default and custom proto_module paths.

#![warn(rust_2018_idioms)]
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    reason = "generated Buffa and validator modules — compile and behavior fixtures, not style targets"
)]

include!(concat!(env!("OUT_DIR"), "/module_tree_mounts.rs"));

macro_rules! module_tree_tests {
    ($name:ident, $messages:path, $consumer:ident) => {
        mod $name {
            use buffa::{Message as _, MessageView as _};
            use protovalidate_buffa::{Validate, ValidationError};
            use $messages as messages;

            fn assert_enum_failure(result: Result<(), ValidationError>, field: &str) {
                let error = result.expect_err("unknown cross-package enum must fail validation");
                assert_eq!(error.violations.len(), 1);
                assert_eq!(error.violations[0].rule_id, "enum.defined_only");
                assert_eq!(
                    error.violations[0].field.elements[0].field_name.as_deref(),
                    Some(field)
                );
            }

            #[test]
            fn cross_package_enums_validate_owned_and_views() {
                use messages::module_tree::$consumer::v1::{__buffa::view::ErrorView, Error};

                // Both top-level and nested enums resolve from the sibling package.
                for bytes in [vec![], vec![0x08, 1, 0x10, 1]] {
                    let owned = Error::decode_from_slice(&bytes).expect("decode consumer error");
                    let view = ErrorView::decode_view(&bytes).expect("decode consumer error view");
                    assert!(owned.validate().is_ok());
                    assert!(view.validate().is_ok());
                }
                for (bytes, field) in [(vec![0x08, 99], "outcome"), (vec![0x10, 99], "detail")] {
                    let owned = Error::decode_from_slice(&bytes).expect("decode consumer error");
                    let view = ErrorView::decode_view(&bytes).expect("decode consumer error view");
                    assert_enum_failure(owned.validate(), field);
                    assert_enum_failure(view.validate(), field);
                }
            }
        }
    };
}

module_tree_tests!(default_runtime, crate::proto, runtime);
module_tree_tests!(default_desktop, crate::proto, desktop);
module_tree_tests!(custom_runtime, crate::custom::messages, runtime);
module_tree_tests!(custom_desktop, crate::custom::messages, desktop);
