use std::io::Cursor;
use std::time::Duration;

use bytes::Bytes;
use http::header::USER_AGENT;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use reqx::{advanced::TlsRootStore, prelude::RedirectPolicy};
use url::Url;

use crate::{
    error::{Error, Result},
    transport::{
        MAX_BUFFERED_RESPONSE_BODY_BYTES, RequestAttemptState, RequestTimer, RetryConfig,
        ServiceErrorAction, TransportRequestBody, default_tls_backend, ensure_method_accepts_body,
        map_reqx_error, prepare_user_agent, record_service_retry, reqx_backoff_source,
        reqx_retry_policy, response_error_from_status, service_error_action,
    },
};

pub(crate) enum BlockingBody {
    Empty,
    Bytes(Bytes),
    Reader {
        reader: Box<dyn std::io::Read + Send + 'static>,
        content_length: Option<u64>,
    },
}

impl TransportRequestBody for BlockingBody {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    fn is_replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::Bytes(_))
    }

    fn clone_for_retry(&self) -> Option<Self> {
        match self {
            Self::Empty => Some(Self::Empty),
            Self::Bytes(b) => Some(Self::Bytes(b.clone())),
            Self::Reader { .. } => None,
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
        tls_root_store: TlsRootStore,
    ) -> Result<Self> {
        let (user_agent_text, user_agent) = prepare_user_agent(user_agent)?;

        let mut builder = reqx::blocking::Client::builder("http://localhost")
            .client_name(user_agent_text)
            .retry_policy(reqx_retry_policy(retry))
            .backoff_source(reqx_backoff_source(retry))
            .redirect_policy(RedirectPolicy::none())
            .max_response_body_bytes(MAX_BUFFERED_RESPONSE_BODY_BYTES)
            .tls_backend(default_tls_backend())
            .tls_root_store(tls_root_store);

        #[cfg(feature = "metrics")]
        {
            builder = builder
                .observer(crate::transport::TransportMetricsObserver)
                .interceptor(crate::transport::TransportMetricsInterceptor);
        }

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
        let mut attempts = RequestAttemptState::new(self.retry, body);
        let max_attempts = attempts.max_attempts();
        let timer = RequestTimer::start();

        for attempt in 1..=max_attempts {
            let current_body = attempts.next_body()?;
            let req = self.build_request(&method, url.clone(), headers.clone(), current_body)?;
            let resp = req
                .send_response()
                .map_err(|err| map_reqx_error("request failed", err))?;
            if let Some(action) = service_error_action(
                self.retry,
                attempt,
                max_attempts,
                resp.status(),
                resp.headers(),
                &resp.text_lossy(),
            ) {
                match action {
                    ServiceErrorAction::RetryAfter(delay) => {
                        record_service_retry(&method);
                        std::thread::sleep(delay);
                        continue;
                    }
                    ServiceErrorAction::ReturnErr(err) => {
                        timer.finish_service_error(&method);
                        return Err(err);
                    }
                }
            }
            timer.finish(&method);
            return Ok(BlockingResponse::from_reqx(resp));
        }

        Err(Error::transport("request failed after retries", None))
    }

    pub(crate) fn send_stream(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<reqx::blocking::ResponseStream> {
        let req = self.build_request(&method, url, headers, body)?;
        req.send_response_stream()
            .map_err(|err| map_reqx_error("request failed", err))
    }

    fn build_request(
        &self,
        method: &Method,
        url: Url,
        headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<reqx::blocking::RequestBuilder<'_>> {
        ensure_method_accepts_body(method, &body)?;

        let mut req = self
            .client
            .request(method.clone(), url.as_str().to_string())
            .header(USER_AGENT, self.user_agent.clone());

        for (name, value) in headers {
            if let Some(name) = name {
                req = req.header(name, value);
            }
        }

        req = match body {
            BlockingBody::Empty => req,
            BlockingBody::Bytes(b) => req.body(b),
            BlockingBody::Reader {
                reader,
                content_length,
            } => {
                let mut req = req.body_reader(reader);
                if let Some(len) = content_length {
                    let value = HeaderValue::from_str(&len.to_string())
                        .map_err(|_| Error::invalid_config("invalid Content-Length header"))?;
                    req = req.header(http::header::CONTENT_LENGTH, value);
                }
                req
            }
        };

        Ok(req)
    }
}

pub(crate) fn response_error(status: StatusCode, headers: &http::HeaderMap, body: &str) -> Error {
    response_error_from_status(status, headers, body)
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;

    mod reqx {
        pub use ::reqx::advanced::TlsRootStore;
    }

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
                ..
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
    fn send_transport_error_redacts_request_path() -> Result<()> {
        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_millis(100)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse("http://127.0.0.1:1/private/object/key?token=secret")
            .map_err(|_| Error::invalid_config("invalid test URL"))?;

        let err = match transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty) {
            Ok(_) => panic!("request should fail with transport error"),
            Err(err) => err,
        };
        let debug = format!("{err:?}");

        match err {
            Error::Transport { message, source } => {
                assert_eq!(message, "request failed");
                let source = source.expect("transport error should preserve a sanitized source");
                let source_text = source.to_string();
                assert!(source_text.contains("http://<redacted-host>:1/<redacted>"));
                assert!(debug.contains("http://<redacted-host>:1/<redacted>"));
                assert!(!message.contains("127.0.0.1"));
                assert!(!source_text.contains("127.0.0.1"));
                assert!(!debug.contains("127.0.0.1"));
                assert!(!message.contains("private/object/key"));
                assert!(!source_text.contains("private/object/key"));
                assert!(!debug.contains("private/object/key"));
                assert!(!message.contains("token=secret"));
                assert!(!source_text.contains("token=secret"));
                assert!(!debug.contains("token=secret"));
            }
            other => panic!("expected transport error, got {other:?}"),
        }
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
            max_retry_after: Duration::from_secs(30),
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
            max_retry_after: Duration::from_secs(30),
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
    fn send_does_not_retry_on_retryable_status_for_non_idempotent_post() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
        };
        let transport = BlockingTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport.send(
            Method::POST,
            url,
            HeaderMap::new(),
            BlockingBody::Bytes(Bytes::from_static(b"hello")),
        )?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
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
            max_retry_after: Duration::from_secs(30),
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
    fn send_retries_when_buffered_body_read_fails() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
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
    fn send_retries_on_embedded_retryable_service_error_xml() -> Result<()> {
        let error_xml =
            "<Error><Code>InternalError</Code><Message>backend failure</Message></Error>";
        let first = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            error_xml.len(),
            error_xml
        )
        .into_bytes();
        let (addr, handle, hits) = spawn_test_server(vec![
            first,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
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
    fn send_retries_on_retryable_service_error_code_from_4xx_body() -> Result<()> {
        let error_xml = "<Error><Code>SlowDown</Code><Message>slow down</Message></Error>";
        let first = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            error_xml.len(),
            error_xml
        )
        .into_bytes();
        let (addr, handle, hits) = spawn_test_server(vec![
            first,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
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
        let mut resp = resp;
        let mut out = Vec::new();
        resp.read_to_end(&mut out)
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
        let mut resp = resp;
        let mut out = Vec::new();
        let read = resp.read_to_end(&mut out);
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
    fn send_does_not_succeed_after_redirect_on_blocking_backend() -> Result<()> {
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

        let outcome = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty);
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        let resp = outcome?;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        Ok(())
    }

    #[test]
    fn send_does_not_succeed_after_query_only_redirect() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /?next=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let transport = BlockingTransport::new(
            RetryConfig::default(),
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::System,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let outcome = transport.send(Method::GET, url, HeaderMap::new(), BlockingBody::Empty);
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        let resp = outcome?;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::FOUND);
        Ok(())
    }

    #[test]
    fn followed_redirect_treats_unparseable_different_uri_as_redirect() {
        let request_url = Url::parse("https://example.com/path?x=1").expect("valid URL");
        assert!(!crate::transport::followed_redirect(
            &request_url,
            request_url.as_str()
        ));
        assert!(crate::transport::followed_redirect(
            &request_url,
            "not-a-valid-uri"
        ));
    }
}
