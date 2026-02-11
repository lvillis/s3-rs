use std::io::Cursor;
use std::time::Duration;

#[cfg(feature = "metrics")]
use std::time::Instant;

use bytes::Bytes;
use http::header::USER_AGENT;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use url::Url;

use crate::{
    error::{Error, Result},
    transport::{RetryConfig, backoff_delay, map_reqx_error, response_error_from_status},
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

pub(crate) struct BlockingResponseBody {
    body: Bytes,
}

impl BlockingResponseBody {
    pub(crate) fn into_reader(self) -> Cursor<Bytes> {
        Cursor::new(self.body)
    }
}

pub(crate) struct BlockingResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl BlockingResponse {
    fn from_reqx(resp: reqx::Response) -> Self {
        Self {
            status: resp.status(),
            headers: resp.headers().clone(),
            body: resp.body().clone(),
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub(crate) fn into_parts(self) -> (http::response::Parts, BlockingResponseBody) {
        let mut response = http::Response::new(BlockingResponseBody { body: self.body });
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response.into_parts()
    }
}

pub(crate) struct BlockingTransport {
    client: reqx::blocking::Client,
    retry: RetryConfig,
    user_agent: HeaderValue,
}

impl BlockingTransport {
    pub(crate) fn new(
        retry: RetryConfig,
        user_agent: Option<String>,
        timeout: Option<Duration>,
        tls_root_store: reqx::TlsRootStore,
    ) -> Result<Self> {
        let user_agent_text = user_agent.unwrap_or_else(default_user_agent);
        let user_agent = HeaderValue::from_str(&user_agent_text)
            .map_err(|_| Error::invalid_config("invalid User-Agent header"))?;

        let mut builder = reqx::blocking::Client::builder("http://localhost")
            .client_name(user_agent_text)
            .retry_policy(reqx::RetryPolicy::disabled())
            .max_response_body_bytes(usize::MAX)
            .tls_backend(default_tls_backend())
            .tls_root_store(tls_root_store);

        if let Some(timeout) = timeout {
            builder = builder.request_timeout(timeout);
        }

        let client = builder
            .build()
            .map_err(|e| map_reqx_error("failed to build HTTP client", e))?;

        Ok(Self {
            client,
            retry,
            user_agent,
        })
    }

    pub(crate) fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<BlockingResponse> {
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
            let req = self.build_request(&method, url.clone(), headers.clone(), current_body)?;

            let resp = match req.send() {
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

                    return Err(map_reqx_error(
                        &format!("request failed: {}", request_context(&method, &url)),
                        err,
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

                let delay =
                    retry_delay_from_response(self.retry, attempt, resp.status(), resp.headers());
                std::thread::sleep(delay);
                continue;
            }

            return Ok(BlockingResponse::from_reqx(resp));
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

    pub(crate) fn send_stream(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<reqx::blocking::ResponseStream> {
        let max_attempts = if body.is_replayable() {
            self.retry.max_attempts
        } else {
            1
        };

        for attempt in 1..=max_attempts {
            let current_body = body
                .clone_for_retry()
                .ok_or_else(|| Error::transport("request body is not replayable", None))?;
            let req = self.build_request(&method, url.clone(), headers.clone(), current_body)?;

            match req.send_stream() {
                Ok(resp) => {
                    if should_retry_status(resp.status()) && attempt < max_attempts {
                        let delay = retry_delay_from_response(
                            self.retry,
                            attempt,
                            resp.status(),
                            resp.headers(),
                        );
                        drop(resp);
                        std::thread::sleep(delay);
                        continue;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    if attempt < max_attempts && should_retry_error(&err) {
                        let delay = backoff_delay(self.retry, attempt);
                        std::thread::sleep(delay);
                        continue;
                    }
                    return Err(map_reqx_error(
                        &format!("request failed: {}", request_context(&method, &url)),
                        err,
                    ));
                }
            }
        }

        Err(Error::transport(
            format!(
                "request failed after retries: {}",
                request_context(&method, &url)
            ),
            None,
        ))
    }

    fn build_request(
        &self,
        method: &Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<reqx::blocking::RequestBuilder<'_>> {
        if matches!(*method, Method::GET | Method::HEAD | Method::DELETE) {
            ensure_empty_body(&body)?;
        }

        let mut req = self
            .client
            .request(method.clone(), url.as_str().to_string())
            .retry_policy(reqx::RetryPolicy::disabled())
            .status_policy(reqx::StatusPolicy::Response)
            .header(USER_AGENT, self.user_agent.clone());

        for (name, value) in headers {
            if let Some(name) = name {
                req = req.header(name, value);
            }
        }

        req = match body {
            BlockingBody::Empty => req,
            BlockingBody::Bytes(b) => req.body_bytes(b),
        };

        Ok(req)
    }
}

pub(crate) fn response_error(status: StatusCode, headers: &http::HeaderMap, body: &str) -> Error {
    response_error_from_status(status, headers, body)
}

fn retry_delay_from_response(
    config: RetryConfig,
    attempt: u32,
    status: StatusCode,
    headers: &HeaderMap,
) -> Duration {
    if status == StatusCode::TOO_MANY_REQUESTS
        && let Some(retry_after) = headers
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

fn should_retry_error(err: &reqx::Error) -> bool {
    matches!(
        err,
        reqx::Error::Transport { .. }
            | reqx::Error::Timeout { .. }
            | reqx::Error::DeadlineExceeded { .. }
            | reqx::Error::ReadBody { .. }
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

fn default_tls_backend() -> reqx::TlsBackend {
    #[cfg(feature = "rustls")]
    {
        return reqx::TlsBackend::RustlsRing;
    }
    #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
    {
        return reqx::TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    reqx::TlsBackend::RustlsRing
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
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
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
