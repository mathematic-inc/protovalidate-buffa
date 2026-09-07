//! Exercise `ConnectRPC`'s HTTP service and client codecs, including gRPC
//! trailers, without sockets or another service generator.
#![cfg(feature = "connect")]

mod support;

use std::error::Error as _;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use buffa_types::google::protobuf::{Empty, EmptyView};
use connectrpc::{
    ConnectRpcService, Protocol, Router, Spec, StreamType,
    client::{CallOptions, ClientConfig, ServiceTransport, call_unary},
    codec::CodecFormat,
    handler::FnHandler,
};
use http_body_util::BodyExt as _;
use protovalidate_buffa::{FieldPath, decode_violations};
use support::single_violation;

#[tokio::test]
async fn service_and_client_preserve_details_across_connect_and_grpc() {
    for (protocol, codec) in [
        (Protocol::Connect, CodecFormat::Proto),
        (Protocol::Connect, CodecFormat::Json),
        (Protocol::Grpc, CodecFormat::Proto),
    ] {
        for count in [1, 1000] {
            for internal in [false, true] {
                let mut diagnostic = single_violation();
                diagnostic.violations = vec![diagnostic.violations[0].clone(); count];
                if internal {
                    diagnostic.runtime_error = Some("private runtime diagnostic".into());
                }
                let expected = diagnostic.clone().into_connect_error();
                let router = Router::new().route::<_, Empty, Empty>(
                    "test.ValidationService",
                    "Check",
                    FnHandler::new(move |_, _: Empty| {
                        let error = diagnostic.clone().into_connect_error();
                        async move { Err::<connectrpc::Response<Empty>, _>(error) }
                    }),
                );
                let transport = ServiceTransport::new(ConnectRpcService::new(router));
                let config = ClientConfig::new("http://localhost".parse().unwrap())
                    .with_protocol(protocol)
                    .with_codec_format(codec);
                let received = call_unary::<_, _, EmptyView<'static>>(
                    &transport,
                    &config,
                    Spec::client("/test.ValidationService/Check", StreamType::Unary),
                    Empty::default(),
                    CallOptions::default(),
                )
                .await
                .unwrap_err();
                assert_eq!(received.code, expected.code);
                assert_eq!(received.message, expected.message);
                assert_eq!(received.details.len(), expected.details.len());
                assert!(received.source().is_none());
                for (actual, expected) in received.details.iter().zip(&expected.details) {
                    let name = if protocol == Protocol::Grpc {
                        "type.googleapis.com/buf.validate.Violations"
                    } else {
                        "buf.validate.Violations"
                    };
                    assert_eq!(actual.type_url, name);
                    assert_eq!(
                        decode_violations(actual).unwrap(),
                        decode_violations(expected).unwrap()
                    );
                }
            }
        }
    }
}

/// The maximum detail fits as valid protobuf, and the actual transport adds
/// Status/Any, base64 and HTTP/2 header-list overhead (32 bytes per header).
#[tokio::test]
async fn grpc_metadata_budget_includes_envelopes_and_base64() {
    let mut diagnostic = single_violation();
    let v = &mut diagnostic.violations[0];
    v.field = FieldPath::default();
    v.rule = FieldPath::default();
    v.rule_id = "x".repeat(4090).into();
    v.for_key = false;
    let error = diagnostic.into_connect_error();
    let mut request_headers = http::HeaderMap::new();
    request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/grpc".parse().unwrap(),
    );
    let response = error.into_http_response(&request_headers);
    let (parts, body) = response.into_parts();
    let collected = body.collect().await.unwrap();
    let mut metadata = parts.headers;
    if let Some(trailers) = collected.trailers() {
        metadata.extend(trailers.clone());
    }
    assert_eq!(metadata["grpc-status"], "3");
    let encoded = metadata["grpc-status-details-bin"].to_str().unwrap();
    let status = STANDARD_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .unwrap();
    assert!(status.len() > 4096);
    assert!(
        String::from_utf8_lossy(&status).contains("type.googleapis.com/buf.validate.Violations")
    );
    let header_list_size: usize = metadata
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 32)
        .sum();
    assert!(
        header_list_size <= 6144,
        "metadata used {header_list_size} bytes"
    );
}

#[tokio::test]
async fn malformed_matching_details_survive_transport_only_as_decode_errors() {
    for protocol in [Protocol::Connect, Protocol::Grpc] {
        for value in [
            None,
            Some("!".to_owned()),
            Some(STANDARD_NO_PAD.encode([0x0a, 0xff])),
            Some(STANDARD_NO_PAD.encode(vec![0; 4097])),
        ] {
            let error = connectrpc::ConnectError::invalid_argument("invalid request").with_detail(
                connectrpc::ErrorDetail {
                    type_url: "buf.validate.Violations".into(),
                    value,
                    debug: None,
                },
            );
            let transport = ServiceTransport::new(tower::service_fn(
                move |request: http::Request<connectrpc::client::ClientBody>| {
                    let response = error.clone().into_http_response(request.headers());
                    async move { Ok::<_, std::convert::Infallible>(response) }
                },
            ));
            let config =
                ClientConfig::new("http://localhost".parse().unwrap()).with_protocol(protocol);
            let received = call_unary::<_, _, EmptyView<'static>>(
                &transport,
                &config,
                Spec::client("/test.ValidationService/Check", StreamType::Unary),
                Empty::default(),
                CallOptions::default(),
            )
            .await
            .unwrap_err();
            assert_eq!(received.code, connectrpc::ErrorCode::InvalidArgument);
            assert_eq!(received.details.len(), 1);
            assert!(decode_violations(&received.details[0]).is_err());
        }
    }
}
