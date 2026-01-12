use std::time::Duration;

#[cfg(feature = "metrics")]
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::{
    error::{Error, Result},
    transport::{RetryConfig, backoff_delay},
};

pub(crate) enum BlockingBody {
    Empty,
    Bytes(Bytes),
}

impl BlockingBody {
    fn is_replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::Bytes(_))
    }

    fn clone_for_retry(&self) -> Option<Self> {
        match self {
            Self::Empty => Some(Self::Empty),
            Self::Bytes(b) => Some(Self::Bytes(b.clone())),
        }
    }
}

pub(crate) struct BlockingTransport {
    agent: ureq::Agent,
    retry: RetryConfig,
    timeout: Option<Duration>,
    user_agent: String,
}

impl BlockingTransport {
    pub(crate) fn new(
        retry: RetryConfig,
        user_agent: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        #[cfg(feature = "rustls")]
        crate::transport::tls::ensure_rustls_crypto_provider();

        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build();

        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
            retry,
            timeout,
            user_agent: user_agent.unwrap_or_else(default_user_agent),
        })
    }

    pub(crate) fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let max_attempts = if body.is_replayable() {
            self.retry.max_attempts
        } else {
            1
        };

        for attempt in 1..=max_attempts {
            #[cfg(feature = "metrics")]
            metrics::counter!("s3_http_attempts_total", "method" => method_label(&method))
                .increment(1);
            #[cfg(feature = "tracing")]
            let _guard = tracing::debug_span!(
                "s3.http",
                method = %method,
                host = url.host_str().unwrap_or(""),
                path = url.path(),
                attempt,
            )
            .entered();
            #[cfg(feature = "metrics")]
            let start = Instant::now();

            let current_body = body
                .clone_for_retry()
                .ok_or_else(|| Error::transport("request body is not replayable", None))?;

            let result = match method.as_str() {
                "GET" => {
                    ensure_empty_body(&current_body)?;
                    let req = apply_headers(
                        self.agent.get(url.as_str()),
                        &headers,
                        &self.user_agent,
                        self.timeout,
                    );
                    req.call()
                }
                "HEAD" => {
                    ensure_empty_body(&current_body)?;
                    let req = apply_headers(
                        self.agent.head(url.as_str()),
                        &headers,
                        &self.user_agent,
                        self.timeout,
                    );
                    req.call()
                }
                "DELETE" => {
                    ensure_empty_body(&current_body)?;
                    let req = apply_headers(
                        self.agent.delete(url.as_str()),
                        &headers,
                        &self.user_agent,
                        self.timeout,
                    );
                    req.call()
                }
                "PUT" => {
                    let req = apply_headers(
                        self.agent.put(url.as_str()),
                        &headers,
                        &self.user_agent,
                        self.timeout,
                    );
                    match current_body {
                        BlockingBody::Empty => req.send_empty(),
                        BlockingBody::Bytes(b) => req.send(b.as_ref()),
                    }
                }
                "POST" => {
                    let req = apply_headers(
                        self.agent.post(url.as_str()),
                        &headers,
                        &self.user_agent,
                        self.timeout,
                    );
                    match current_body {
                        BlockingBody::Empty => req.send_empty(),
                        BlockingBody::Bytes(b) => req.send(b.as_ref()),
                    }
                }
                _ => return Err(Error::invalid_config("unsupported HTTP method")),
            };

            let resp = match result {
                Ok(resp) => resp,
                Err(err) => {
                    if attempt < max_attempts && should_retry_error(&err) {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "s3_http_retries_total",
                            "method" => method_label(&method),
                            "reason" => "transport"
                        )
                        .increment(1);
                        #[cfg(feature = "tracing")]
                        tracing::debug!(error = ?err, "retrying after transport error");

                        let delay = backoff_delay(self.retry, attempt);
                        std::thread::sleep(delay);
                        continue;
                    }

                    #[cfg(feature = "metrics")]
                    metrics::counter!(
                        "s3_http_errors_total",
                        "method" => method_label(&method),
                        "kind" => "transport"
                    )
                    .increment(1);

                    return Err(Error::transport(
                        format!("request failed: {}", request_context(&method, &url)),
                        Some(Box::new(err)),
                    ));
                }
            };

            #[cfg(feature = "metrics")]
            {
                metrics::counter!(
                    "s3_http_responses_total",
                    "method" => method_label(&method),
                    "class" => status_class(resp.status()),
                )
                .increment(1);
                metrics::histogram!(
                    "s3_http_request_duration_seconds",
                    "method" => method_label(&method),
                )
                .record(start.elapsed().as_secs_f64());
            }

            if should_retry_status(resp.status()) && attempt < max_attempts {
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "s3_http_retries_total",
                    "method" => method_label(&method),
                    "reason" => "status"
                )
                .increment(1);
                #[cfg(feature = "tracing")]
                tracing::debug!(status = %resp.status(), "retrying after response status");

                let delay = retry_delay_from_response(self.retry, attempt, &resp);
                std::thread::sleep(delay);
                continue;
            }

            return Ok(resp);
        }

        #[cfg(feature = "metrics")]
        metrics::counter!(
            "s3_http_errors_total",
            "method" => method_label(&method),
            "kind" => "exhausted"
        )
        .increment(1);
        Err(Error::transport(
            format!(
                "request failed after retries: {}",
                request_context(&method, &url)
            ),
            None,
        ))
    }
}

pub(crate) fn response_error(status: StatusCode, headers: &http::HeaderMap, body: &str) -> Error {
    let request_id = headers
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = headers
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);

        return Error::RateLimited {
            retry_after,
            request_id,
        };
    }

    let snippet = crate::util::text::truncate_snippet(body, 4096);

    if let Some(parsed) = crate::util::xml::parse_error_xml(body) {
        return Error::Api {
            status,
            code: parsed.code,
            message: parsed.message,
            request_id: parsed.request_id.or(request_id),
            host_id: parsed.host_id,
            body_snippet: Some(snippet),
        };
    }

    Error::Api {
        status,
        code: None,
        message: None,
        request_id,
        host_id: None,
        body_snippet: Some(snippet),
    }
}

fn retry_delay_from_response(
    config: RetryConfig,
    attempt: u32,
    resp: &ureq::http::Response<ureq::Body>,
) -> Duration {
    if resp.status() == StatusCode::TOO_MANY_REQUESTS
        && let Some(retry_after) = resp
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_secs(retry_after);
    }
    backoff_delay(config, attempt)
}

fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn should_retry_error(err: &ureq::Error) -> bool {
    matches!(
        err,
        ureq::Error::Timeout(_)
            | ureq::Error::Protocol(_)
            | ureq::Error::Io(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
    )
}

fn request_context(method: &Method, url: &Url) -> String {
    let authority = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => String::new(),
    };

    if authority.is_empty() {
        format!("{method} {}", url.path())
    } else {
        format!("{method} {authority}{}", url.path())
    }
}

fn ensure_empty_body(body: &BlockingBody) -> Result<()> {
    match body {
        BlockingBody::Empty => Ok(()),
        BlockingBody::Bytes(_) => Err(Error::invalid_config(
            "this operation does not accept a request body",
        )),
    }
}

#[cfg(feature = "metrics")]
fn status_class(status: StatusCode) -> &'static str {
    if status.is_informational() {
        "1xx"
    } else if status.is_success() {
        "2xx"
    } else if status.is_redirection() {
        "3xx"
    } else if status.is_client_error() {
        "4xx"
    } else if status.is_server_error() {
        "5xx"
    } else {
        "other"
    }
}

#[cfg(feature = "metrics")]
fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "PUT" => "PUT",
        "HEAD" => "HEAD",
        "DELETE" => "DELETE",
        "POST" => "POST",
        _ => "OTHER",
    }
}

fn apply_headers<B>(
    mut req: ureq::RequestBuilder<B>,
    headers: &HeaderMap,
    user_agent: &str,
    timeout: Option<Duration>,
) -> ureq::RequestBuilder<B> {
    req = req.header(http::header::USER_AGENT, user_agent);
    for (name, value) in headers.iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        req = req.header(name.as_str(), value_str);
    }

    if let Some(timeout) = timeout {
        req = req.config().timeout_global(Some(timeout)).build();
    }

    req
}

fn default_user_agent() -> String {
    format!("s3/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_error_extracts_rate_limit() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-request-id", http::HeaderValue::from_static("req-1"));
        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("3"),
        );

        let err = response_error(StatusCode::TOO_MANY_REQUESTS, &headers, "slow down");
        match err {
            Error::RateLimited {
                retry_after,
                request_id,
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3)));
                assert_eq!(request_id.as_deref(), Some("req-1"));
            }
            other => panic!("expected rate limited error, got {other:?}"),
        }
    }

    #[test]
    fn response_error_parses_xml_error_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            http::HeaderValue::from_static("req-outer"),
        );

        let body = r#"
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>req-inner</RequestId>
  <HostId>host-1</HostId>
</Error>
"#;

        let err = response_error(StatusCode::FORBIDDEN, &headers, body);
        match err {
            Error::Api {
                status,
                code,
                message,
                request_id,
                host_id,
                body_snippet,
            } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(code.as_deref(), Some("AccessDenied"));
                assert_eq!(message.as_deref(), Some("Access Denied"));
                assert_eq!(request_id.as_deref(), Some("req-inner"));
                assert_eq!(host_id.as_deref(), Some("host-1"));
                assert!(body_snippet.unwrap_or_default().contains("AccessDenied"));
            }
            other => panic!("expected api error, got {other:?}"),
        }
    }

    #[test]
    fn send_returns_response_for_http_error_status() -> Result<()> {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| Error::transport("failed to bind test server", Some(Box::new(e))))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::transport("failed to configure test server", Some(Box::new(e))))?;
        let addr = listener.local_addr().map_err(|e| {
            Error::transport("failed to read test server address", Some(Box::new(e)))
        })?;

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = Vec::new();
                        let mut buf = [0u8; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    request.extend_from_slice(&buf[..n]);
                                    if request.len() > 64 * 1024 {
                                        break;
                                    }
                                }
                                Err(err)
                                    if matches!(
                                        err.kind(),
                                        ErrorKind::WouldBlock | ErrorKind::TimedOut
                                    ) =>
                                {
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                        break;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = BlockingTransport::new(retry, None, Some(Duration::from_secs(5)))?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp_result = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty);
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        let resp = resp_result?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}
