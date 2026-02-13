use std::time::Duration;

#[cfg(feature = "async")]
pub(crate) mod async_transport;
#[cfg(feature = "blocking")]
pub(crate) mod blocking_transport;

#[cfg(any(feature = "async", feature = "blocking"))]
use http::{Method, StatusCode};
#[cfg(any(feature = "async", feature = "blocking"))]
use url::Url;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryConfig {
    pub(crate) max_attempts: u32,
    pub(crate) base_delay: Duration,
    pub(crate) max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        }
    }
}

pub(crate) fn backoff_delay(config: RetryConfig, attempt: u32) -> Duration {
    let attempt = attempt.saturating_sub(1);
    let factor = 1u32 << attempt.min(16);
    let millis = config
        .base_delay
        .as_millis()
        .saturating_mul(u128::from(factor));
    let capped = millis.min(config.max_delay.as_millis());

    let jitter = jitter_millis(capped);
    Duration::from_millis(jitter as u64)
}

fn jitter_millis(max_millis: u128) -> u128 {
    if max_millis <= 1 {
        return max_millis;
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128)
        .unwrap_or(0);

    nanos % max_millis
}

#[cfg(any(feature = "async", feature = "blocking"))]
fn request_id_from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("x-amz-request-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn retry_after_from_headers(headers: &http::HeaderMap) -> Option<Duration> {
    headers
        .get(http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_value)
}

#[cfg(any(feature = "async", feature = "blocking"))]
fn parse_retry_after_value(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let when = httpdate::parse_http_date(value).ok()?;
    let now = std::time::SystemTime::now();
    match when.duration_since(now) {
        Ok(delay) => Some(delay),
        Err(_) => Some(Duration::from_secs(0)),
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn response_error_from_status(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &str,
) -> crate::error::Error {
    let request_id = request_id_from_headers(headers);

    if status == http::StatusCode::TOO_MANY_REQUESTS {
        return crate::error::Error::RateLimited {
            retry_after: retry_after_from_headers(headers),
            request_id,
        };
    }

    let snippet = crate::util::text::truncate_snippet(body, 4096);
    if let Some(parsed) = crate::util::xml::parse_error_xml(body) {
        return crate::error::Error::Api {
            status,
            code: parsed.code,
            message: parsed.message,
            request_id: parsed.request_id.or(request_id),
            host_id: parsed.host_id,
            body_snippet: Some(snippet),
        };
    }

    crate::error::Error::Api {
        status,
        code: None,
        message: None,
        request_id,
        host_id: None,
        body_snippet: Some(snippet),
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn response_service_error(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &str,
) -> Option<crate::error::Error> {
    let parsed = crate::util::xml::parse_error_xml(body)?;
    if parsed.code.is_none()
        && parsed.message.is_none()
        && parsed.request_id.is_none()
        && parsed.host_id.is_none()
    {
        return None;
    }

    Some(response_error_from_status(status, headers, body))
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn map_reqx_error(message: &str, err: reqx::Error) -> crate::error::Error {
    match err {
        reqx::Error::HttpStatus {
            status,
            headers,
            body,
            ..
        } => {
            let status = http::StatusCode::from_u16(status)
                .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
            response_error_from_status(status, &headers, &body)
        }
        reqx::Error::DeserializeJson { source, .. } => crate::error::Error::decode(
            format!("{message}: failed to decode response json"),
            Some(Box::new(source)),
        ),
        other => crate::error::Error::transport(message, Some(Box::new(other))),
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn should_retry_error(err: &reqx::Error) -> bool {
    matches!(
        err,
        reqx::Error::Transport { .. }
            | reqx::Error::Timeout { .. }
            | reqx::Error::DeadlineExceeded { .. }
            | reqx::Error::ReadBody { .. }
    )
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn is_retryable_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn followed_redirect(request_url: &Url, response_uri: &str) -> bool {
    if response_uri == request_url.as_str() {
        return false;
    }

    let Ok(response_url) = Url::parse(response_uri) else {
        // Treat an unparseable-but-different URI as suspicious to avoid returning
        // silently redirected successes.
        return true;
    };

    request_url.scheme() != response_url.scheme()
        || request_url.username() != response_url.username()
        || request_url.password() != response_url.password()
        || request_url.host_str() != response_url.host_str()
        || request_url.port_or_known_default() != response_url.port_or_known_default()
        || request_url.path() != response_url.path()
        || request_url.query() != response_url.query()
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn unexpected_redirect_error(
    method: &Method,
    request_url: &Url,
    response_uri: &str,
) -> crate::error::Error {
    crate::error::Error::transport(
        format!(
            "unexpected redirect followed for {method} {} -> {response_uri}",
            request_url.as_str()
        ),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_is_capped_and_non_negative() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        };

        let d1 = backoff_delay(cfg, 1);
        let d2 = backoff_delay(cfg, 2);
        let d3 = backoff_delay(cfg, 3);
        let d99 = backoff_delay(cfg, 99);

        assert!(d1 < Duration::from_millis(200));
        assert!(d2 < Duration::from_millis(400));
        assert!(d3 < Duration::from_millis(800));
        assert!(d99 < cfg.max_delay);
    }

    #[test]
    fn backoff_delay_zero_base_is_zero() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_secs(2),
        };

        assert_eq!(backoff_delay(cfg, 1), Duration::from_millis(0));
        assert_eq!(backoff_delay(cfg, 10), Duration::from_millis(0));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn map_reqx_error_http_status_is_mapped_to_api_error() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            http::HeaderValue::from_static("req-123"),
        );
        let body = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";

        let err = reqx::Error::HttpStatus {
            status: 403,
            method: http::Method::GET,
            uri: "https://example.com/path".to_string(),
            headers: Box::new(headers),
            body: body.to_string(),
        };

        match map_reqx_error("request failed", err) {
            crate::error::Error::Api {
                status,
                code,
                message,
                request_id,
                ..
            } => {
                assert_eq!(status, http::StatusCode::FORBIDDEN);
                assert_eq!(code.as_deref(), Some("AccessDenied"));
                assert_eq!(message.as_deref(), Some("Access Denied"));
                assert_eq!(request_id.as_deref(), Some("req-123"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn retry_after_from_headers_supports_http_date() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );

        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(0))
        );
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn retry_after_from_headers_supports_seconds() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("7"),
        );

        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(7))
        );
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn response_error_from_status_maps_common_status_matrix() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            http::HeaderValue::from_static("req-matrix"),
        );

        let api_statuses = [
            http::StatusCode::BAD_REQUEST,
            http::StatusCode::FORBIDDEN,
            http::StatusCode::NOT_FOUND,
            http::StatusCode::CONFLICT,
            http::StatusCode::PRECONDITION_FAILED,
            http::StatusCode::INTERNAL_SERVER_ERROR,
            http::StatusCode::SERVICE_UNAVAILABLE,
        ];

        for status in api_statuses {
            match response_error_from_status(status, &headers, "plain error body") {
                crate::error::Error::Api {
                    status: got_status,
                    request_id,
                    ..
                } => {
                    assert_eq!(got_status, status);
                    assert_eq!(request_id.as_deref(), Some("req-matrix"));
                }
                other => panic!("expected Api for {status}, got {other:?}"),
            }
        }

        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("3"),
        );
        match response_error_from_status(http::StatusCode::TOO_MANY_REQUESTS, &headers, "throttled")
        {
            crate::error::Error::RateLimited {
                retry_after,
                request_id,
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3)));
                assert_eq!(request_id.as_deref(), Some("req-matrix"));
            }
            other => panic!("expected RateLimited for 429, got {other:?}"),
        }
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn followed_redirect_flags_query_loss_when_authority_and_path_match() {
        let request_url =
            Url::parse("http://127.0.0.1:9000/demo-bucket?list-type=2&max-keys=1").unwrap();
        let response_uri = "http://127.0.0.1:9000/demo-bucket";
        assert!(followed_redirect(&request_url, response_uri));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn followed_redirect_still_flags_path_change() {
        let request_url = Url::parse("http://127.0.0.1:9000/demo-bucket?uploads=").unwrap();
        let response_uri = "http://127.0.0.1:9000/other-bucket";
        assert!(followed_redirect(&request_url, response_uri));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn followed_redirect_flags_query_change_when_response_includes_query() {
        let request_url = Url::parse("http://127.0.0.1:9000/demo-bucket?uploads=").unwrap();
        let response_uri = "http://127.0.0.1:9000/demo-bucket?uploads=1";
        assert!(followed_redirect(&request_url, response_uri));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn followed_redirect_flags_added_query() {
        let request_url = Url::parse("http://127.0.0.1:9000/demo-bucket").unwrap();
        let response_uri = "http://127.0.0.1:9000/demo-bucket?list-type=2";
        assert!(followed_redirect(&request_url, response_uri));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn response_service_error_detects_embedded_service_error_xml() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            http::HeaderValue::from_static("req-success-xml"),
        );
        let body = r#"<Error><Code>InternalError</Code><Message>backend failure</Message></Error>"#;

        let err = response_service_error(http::StatusCode::OK, &headers, body)
            .expect("expected embedded error to be detected");
        match err {
            crate::error::Error::Api {
                status,
                code,
                request_id,
                ..
            } => {
                assert_eq!(status, http::StatusCode::OK);
                assert_eq!(code.as_deref(), Some("InternalError"));
                assert_eq!(request_id.as_deref(), Some("req-success-xml"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn response_service_error_ignores_non_error_success_body() {
        assert!(
            response_service_error(
                http::StatusCode::OK,
                &http::HeaderMap::new(),
                "<ListBucketResult/>"
            )
            .is_none()
        );
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn response_service_error_preserves_retryable_service_code_on_4xx() {
        let body = r#"<Error><Code>SlowDown</Code><Message>slow down</Message></Error>"#;
        let err =
            response_service_error(http::StatusCode::BAD_REQUEST, &http::HeaderMap::new(), body)
                .expect("expected embedded service error");
        assert!(err.is_retryable());
    }

    #[cfg(all(
        any(feature = "async", feature = "blocking"),
        feature = "credentials-imds"
    ))]
    #[test]
    fn map_reqx_error_deserialize_json_is_sanitized() {
        let source = serde_json::from_slice::<serde_json::Value>(b"{not-json")
            .expect_err("invalid json should produce an error");
        let err = reqx::Error::DeserializeJson {
            source,
            body: "token=super-secret-value".to_string(),
        };

        let mapped = map_reqx_error("request failed", err);
        match mapped {
            crate::error::Error::Decode { source, .. } => {
                assert!(source.is_some());
            }
            other => panic!("expected Decode error, got {other:?}"),
        }
    }
}
