//! Two source files share one validator include; a sibling package supplies an enum.
//!
//! Run: `cargo run -p protovalidate-buffa-packaging-examples --bin split_package`
#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::Validate as _;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    elided_lifetimes_in_paths,
    unused_imports,
    reason = "Buffa and validator generated code"
)]
mod example {
    pub mod money {
        pub mod v1 {
            // This package has only an enum, so it needs no validator file.
            include!(concat!(env!("OUT_DIR"), "/example.money.v1.rs"));
        }
    }
    pub mod orders {
        pub mod v1 {
            // Enum validation uses protobuf paths beginning at `example`.
            use crate::example;

            include!(concat!(env!("OUT_DIR"), "/example.orders.v1.rs"));
            include!(concat!(env!("OUT_DIR"), "/example.orders.v1.validate.rs"));
        }
    }
}

fn main() {
    validate_orders();
    println!(
        "split_package: orders, line items, and cross-package currency enums validated for owned messages and views"
    );
}

fn validate_orders() {
    use example::orders::v1::{__buffa::view::OrderView, LineItem, Order};

    for (quantity, currency, expected_rule) in [
        (2, 1, None),
        (0, 1, Some("int32.gt")),
        (2, 99, Some("enum.defined_only")),
    ] {
        let order = Order {
            items: vec![LineItem {
                quantity,
                currency: buffa::EnumValue::from(currency),
                ..Default::default()
            }],
            ..Default::default()
        };
        let bytes = order.encode_to_vec();
        let view = OrderView::decode_view(&bytes).expect("decode order view");
        for result in [order.validate(), view.validate()] {
            if let Some(rule) = expected_rule {
                let error = result.expect_err("invalid line item must fail");
                assert_eq!(error.violations[0].rule_id, rule);
                assert_eq!(
                    error.violations[0].field.elements[0].field_name.as_deref(),
                    Some("items")
                );
            } else {
                result.expect("valid order");
            }
        }
    }
    assert_eq!(
        Order::default().validate().unwrap_err().violations[0].rule_id,
        "repeated.min_items"
    );
}

#[test]
fn split_package_validates_nested_messages_and_cross_package_enums() {
    validate_orders();
}
