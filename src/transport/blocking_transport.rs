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
    transport::{
        RetryConfig, backoff_delay, map_reqx_error, response_error_from_status,
        retry_after_from_headers,
    },
};

const MAX_BUFFERED_RESPONSE_BODY_BYTES: usize = 32 * 1024 * 1024;

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
            .redirect_policy(reqx::RedirectPolicy::none())
            .max_response_body_bytes(MAX_BUFFERED_RESPONSE_BODY_BYTES)
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
            .redirect_policy(reqx::RedirectPolicy::none())
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
        && let Some(retry_after) = retry_after_from_headers(headers)
    {
        return retry_after;
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
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;

    fn spawn_test_server(
        responses: Vec<Vec<u8>>,
    ) -> Result<(SocketAddr, std::thread::JoinHandle<()>, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| Error::transport("failed to bind test server", Some(Box::new(e))))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| Error::transport("failed to configure test server", Some(Box::new(e))))?;
        let addr = listener.local_addr().map_err(|e| {
            Error::transport("failed to read test server address", Some(Box::new(e)))
        })?;

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_thread = hits.clone();

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            for response in responses {
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
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                            hits_thread.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
            }
        });

        Ok((addr, handle, hits))
    }

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
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

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
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[test]
    fn send_head_with_content_encoding_and_empty_body_returns_ok() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

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

        let resp = transport.send(Method::HEAD, url, HeaderMap::new(), BlockingBody::Empty)?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::OK);
        let (parts, body) = resp.into_parts();
        assert_eq!(
            parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("zstd")
        );
        assert!(body.into_reader().into_inner().is_empty());
        Ok(())
    }

    #[test]
    fn send_does_not_retry_on_non_retryable_4xx_status() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
        };
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[test]
    fn send_retries_on_retryable_5xx_status() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
        };
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn send_retries_on_transport_error_for_replayable_body() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            Vec::new(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
        };
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn send_stream_preserves_content_encoding_and_raw_bytes() -> Result<()> {
        let gzipped = vec![
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9,
            0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
        ];
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            gzipped.len()
        );
        let mut wire = response.into_bytes();
        wire.extend_from_slice(&gzipped);
        let (addr, handle, _) = spawn_test_server(vec![wire])?;

        let retry = RetryConfig::default();
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp =
            transport.send_stream(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        let mut reader = resp.into_body().into_reader();
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert_eq!(out, gzipped);
        Ok(())
    }

    #[test]
    fn send_stream_body_read_error_is_observable() -> Result<()> {
        let (addr, handle, _) = spawn_test_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc".to_vec(),
        ])?;

        let retry = RetryConfig::default();
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp =
            transport.send_stream(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        let mut reader = resp.into_body().into_reader();
        let mut out = Vec::new();
        let read = reader.read_to_end(&mut out);
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert!(read.is_err(), "expected read error for truncated response");
        Ok(())
    }

    #[test]
    fn send_stream_into_response_limited_enforces_limit() -> Result<()> {
        let payload = "x".repeat(2048);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        let (addr, handle, _) = spawn_test_server(vec![response.into_bytes()])?;

        let retry = RetryConfig::default();
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp =
            transport.send_stream(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        let limited = resp.into_response_limited(1024);
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert!(limited.is_err(), "expected body limit error");
        Ok(())
    }

    #[test]
    fn send_follows_redirect_on_blocking_backend() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig::default();
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty)?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }
}
