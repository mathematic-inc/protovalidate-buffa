#![cfg(feature = "json")]

mod support;

use buffa::json_helpers::ProtoJson;
use protovalidate_buffa::proto;
use support::single_violation;

#[test]
fn canonical_json_serializes_and_decodes_the_reexported_details() {
    let details = single_violation().to_proto();
    let json = serde_json::to_value(ProtoJson(&details)).unwrap();
    let violation = &json["violations"][0];
    assert_eq!(violation["ruleId"], "address.code");
    assert_eq!(violation["message"], "invalid value: private-value");
    assert_eq!(violation["forKey"], true);
    let field = &violation["field"]["elements"];
    assert_eq!(field[0]["fieldNumber"], 7);
    assert_eq!(field[0]["fieldType"], "TYPE_MESSAGE");
    assert_eq!(field[0]["stringKey"], "private-key");
    // Canonical protobuf JSON represents uint64 values as strings.
    assert_eq!(field[1]["index"], "0");
    assert_eq!(violation["rule"]["elements"][0]["index"], "2");
    let decoded: proto::Violations = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, details);
}
