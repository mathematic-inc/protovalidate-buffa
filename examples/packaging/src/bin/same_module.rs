//! Include a package's types and validators in one handwritten module.
//!
//! Run: `cargo run -p protovalidate-buffa-packaging-examples --bin same_module`
#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::Validate as _;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unused_imports,
    reason = "Buffa and validator generated code"
)]
mod users {
    include!(concat!(env!("OUT_DIR"), "/example.users.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/user.validate.rs"));
}

fn main() {
    validate_users();
    println!(
        "same_module: valid email accepted; invalid email rejected for owned messages and views"
    );
}

fn validate_users() {
    for (email, valid) in [("ada@example.com", true), ("invalid", false)] {
        let user = users::User {
            email: email.into(),
            ..Default::default()
        };
        let bytes = user.encode_to_vec();
        let view = users::__buffa::view::UserView::decode_view(&bytes).expect("decode user view");
        assert_eq!(user.validate().is_ok(), valid);
        assert_eq!(view.validate().is_ok(), valid);
        if !valid {
            let error = user.validate().unwrap_err();
            assert_eq!(error.violations[0].rule_id, "string.email");
        }
    }
}

#[test]
fn same_module_validates_owned_and_borrowed_users() {
    validate_users();
}
