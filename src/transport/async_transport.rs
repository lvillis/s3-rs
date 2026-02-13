use std::{io, pin::Pin, time::Duration};

#[cfg(feature = "metrics")]
use std::time::Instant;

use bytes::Bytes;
use futures_core::Stream;
use http::header::{CONTENT_LENGTH, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use reqx::{Client as HttpClient, Response as ReqxResponse};
use url::Url;

#[cfg(feature = "metrics")]
use crate::transport::{method_label, status_class};
use crate::{
    error::{Error, Result},
    transport::{
        RetryConfig, backoff_delay, default_tls_backend, default_user_agent, followed_redirect,
        is_retryable_method, map_reqx_error, response_error_from_status, response_service_error,
        retry_delay_from_response, should_retry_error, should_retry_status,
        unexpected_redirect_error,
    },
};

const MAX_BUFFERED_RESPONSE_BODY_BYTES: usize = 32 * 1024 * 1024;

type AsyncByteStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, io::Error>> + Send + Sync + 'static>>;

pub(crate) enum AsyncBody {
    Empty,
    Bytes(Bytes),
    Stream {
        stream: AsyncByteStream,
        content_length: Option<u64>,
    },
}

impl AsyncBody {
    fn is_replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::Bytes(_))
    }

    fn clone_for_retry(&self) -> Option<Self> {
        match self {
            Self::Empty => Some(Self::Empty),
            Self::Bytes(b) => Some(Self::Bytes(b.clone())),
            Self::Stream { .. } => None,
        }
    }
}

pub(crate) struct AsyncTransport {
    client: HttpClient,
    retry: RetryConfig,
    user_agent: HeaderValue,
}

#[derive(Clone, Debug)]
pub(crate) struct AsyncResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl AsyncResponse {
    pub(crate) fn from_reqx(resp: ReqxResponse) -> Self {
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

    pub(crate) fn body(&self) -> &Bytes {
        &self.body
    }

    pub(crate) async fn text(self) -> std::result::Result<String, io::Error> {
        Ok(String::from_utf8_lossy(&self.body).into_owned())
    }
}

impl AsyncTransport {
    pub(crate) fn new(
        retry: RetryConfig,
        user_agent: Option<String>,
        timeout: Option<Duration>,
        tls_root_store: reqx::TlsRootStore,
    ) -> Result<Self> {
        let user_agent_text = user_agent.unwrap_or_else(default_user_agent);
        let user_agent = HeaderValue::from_str(&user_agent_text)
            .map_err(|_| Error::invalid_config("invalid User-Agent header"))?;

        let mut builder = HttpClient::builder("http://localhost")
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

    pub(crate) async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: AsyncBody,
    ) -> Result<AsyncResponse> {
        match body {
            body @ AsyncBody::Stream { .. } => {
                #[cfg(feature = "metrics")]
                metrics::counter!("s3_http_attempts_total", "method" => method_label(&method))
                    .increment(1);
                #[cfg(feature = "tracing")]
                let _guard = tracing::debug_span!(
                    "s3.http",
                    method = %method,
                    host = crate::transport::redacted_host_for_trace(&url),
                    path = crate::transport::redacted_path_for_trace(&url),
                    has_query = url.query().is_some(),
                    attempt = 1u32,
                )
                .entered();
                #[cfg(feature = "metrics")]
                let start = Instant::now();

                let req = self.build_request(&method, url.clone(), headers, body)?;
                match req.send_stream().await {
                    Ok(resp) => {
                        if followed_redirect(&url, resp.uri()) {
                            #[cfg(feature = "metrics")]
                            metrics::counter!(
                                "s3_http_errors_total",
                                "method" => method_label(&method),
                                "kind" => "redirect"
                            )
                            .increment(1);
                            return Err(unexpected_redirect_error(&method, &url, resp.uri()));
                        }
                        let resp = resp
                            .into_response_limited(MAX_BUFFERED_RESPONSE_BODY_BYTES)
                            .await
                            .map_err(|err| map_reqx_error("request failed", err))?;
                        if let Some(err) = response_service_error(
                            resp.status(),
                            resp.headers(),
                            &resp.text_lossy(),
                        ) {
                            if resp.status().is_success() {
                                #[cfg(feature = "metrics")]
                                metrics::counter!(
                                    "s3_http_errors_total",
                                    "method" => method_label(&method),
                                    "kind" => "service"
                                )
                                .increment(1);
                                return Err(err);
                            }
                        }
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
                        Ok(AsyncResponse::from_reqx(resp))
                    }
                    Err(err) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "s3_http_errors_total",
                            "method" => method_label(&method),
                            "kind" => "transport"
                        )
                        .increment(1);
                        Err(map_reqx_error("request failed", err))
                    }
                }
            }
            replayable => {
                let max_attempts = if replayable.is_replayable() && is_retryable_method(&method) {
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
                        host = crate::transport::redacted_host_for_trace(&url),
                        path = crate::transport::redacted_path_for_trace(&url),
                        has_query = url.query().is_some(),
                        attempt,
                    )
                    .entered();
                    #[cfg(feature = "metrics")]
                    let start = Instant::now();

                    let current_body = replayable
                        .clone_for_retry()
                        .ok_or_else(|| Error::transport("request body is not replayable", None))?;
                    let req =
                        self.build_request(&method, url.clone(), headers.clone(), current_body)?;

                    match req.send_stream().await {
                        Ok(resp) => {
                            if followed_redirect(&url, resp.uri()) {
                                #[cfg(feature = "metrics")]
                                metrics::counter!(
                                    "s3_http_errors_total",
                                    "method" => method_label(&method),
                                    "kind" => "redirect"
                                )
                                .increment(1);
                                return Err(unexpected_redirect_error(&method, &url, resp.uri()));
                            }
                            #[cfg(feature = "metrics")]
                            metrics::counter!(
                                "s3_http_responses_total",
                                "method" => method_label(&method),
                                "class" => status_class(resp.status()),
                            )
                            .increment(1);
                            #[cfg(feature = "metrics")]
                            metrics::histogram!(
                                "s3_http_request_duration_seconds",
                                "method" => method_label(&method),
                            )
                            .record(start.elapsed().as_secs_f64());

                            if should_retry_status(resp.status()) && attempt < max_attempts {
                                #[cfg(feature = "metrics")]
                                metrics::counter!(
                                    "s3_http_retries_total",
                                    "method" => method_label(&method),
                                    "reason" => "status"
                                )
                                .increment(1);
                                let delay = retry_delay_from_response(
                                    self.retry,
                                    attempt,
                                    resp.status(),
                                    resp.headers(),
                                );
                                drop(resp);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            let resp = match resp
                                .into_response_limited(MAX_BUFFERED_RESPONSE_BODY_BYTES)
                                .await
                            {
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
                                        let delay = backoff_delay(self.retry, attempt);
                                        tokio::time::sleep(delay).await;
                                        continue;
                                    }
                                    return Err(map_reqx_error("request failed", err));
                                }
                            };
                            if let Some(err) = response_service_error(
                                resp.status(),
                                resp.headers(),
                                &resp.text_lossy(),
                            ) {
                                if attempt < max_attempts && err.is_retryable() {
                                    #[cfg(feature = "metrics")]
                                    metrics::counter!(
                                        "s3_http_retries_total",
                                        "method" => method_label(&method),
                                        "reason" => "service"
                                    )
                                    .increment(1);
                                    let delay = backoff_delay(self.retry, attempt);
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                                if resp.status().is_success() {
                                    #[cfg(feature = "metrics")]
                                    metrics::counter!(
                                        "s3_http_errors_total",
                                        "method" => method_label(&method),
                                        "kind" => "service"
                                    )
                                    .increment(1);
                                    return Err(err);
                                }
                            }
                            return Ok(AsyncResponse::from_reqx(resp));
                        }
                        Err(err) => {
                            if attempt < max_attempts && should_retry_error(&err) {
                                #[cfg(feature = "metrics")]
                                metrics::counter!(
                                    "s3_http_retries_total",
                                    "method" => method_label(&method),
                                    "reason" => "transport"
                                )
                                .increment(1);
                                let delay = backoff_delay(self.retry, attempt);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            #[cfg(feature = "metrics")]
                            metrics::counter!(
                                "s3_http_errors_total",
                                "method" => method_label(&method),
                                "kind" => "transport"
                            )
                            .increment(1);
                            return Err(map_reqx_error("request failed", err));
                        }
                    }
                }

                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "s3_http_errors_total",
                    "method" => method_label(&method),
                    "kind" => "exhausted"
                )
                .increment(1);
                Err(Error::transport("request failed after retries", None))
            }
        }
    }

    pub(crate) async fn send_stream(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: AsyncBody,
    ) -> Result<reqx::ResponseStream> {
        match body {
            body @ AsyncBody::Stream { .. } => {
                let req = self.build_request(&method, url.clone(), headers, body)?;
                let resp = req
                    .send_stream()
                    .await
                    .map_err(|err| map_reqx_error("request failed", err))?;
                if followed_redirect(&url, resp.uri()) {
                    return Err(unexpected_redirect_error(&method, &url, resp.uri()));
                }
                Ok(resp)
            }
            replayable => {
                let max_attempts = if is_retryable_method(&method) {
                    self.retry.max_attempts
                } else {
                    1
                };
                for attempt in 1..=max_attempts {
                    let current_body = replayable
                        .clone_for_retry()
                        .ok_or_else(|| Error::transport("request body is not replayable", None))?;
                    let req =
                        self.build_request(&method, url.clone(), headers.clone(), current_body)?;

                    match req.send_stream().await {
                        Ok(resp) => {
                            if followed_redirect(&url, resp.uri()) {
                                return Err(unexpected_redirect_error(&method, &url, resp.uri()));
                            }
                            if should_retry_status(resp.status()) && attempt < max_attempts {
                                let delay = retry_delay_from_response(
                                    self.retry,
                                    attempt,
                                    resp.status(),
                                    resp.headers(),
                                );
                                drop(resp);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            return Ok(resp);
                        }
                        Err(err) => {
                            if attempt < max_attempts && should_retry_error(&err) {
                                let delay = backoff_delay(self.retry, attempt);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            return Err(map_reqx_error("request failed", err));
                        }
                    }
                }

                Err(Error::transport("request failed after retries", None))
            }
        }
    }

    fn build_request(
        &self,
        method: &Method,
        url: Url,
        headers: HeaderMap,
        body: AsyncBody,
    ) -> Result<reqx::RequestBuilder<'_>> {
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
            AsyncBody::Empty => req,
            AsyncBody::Bytes(b) => req.body_bytes(b),
            AsyncBody::Stream {
                stream,
                content_length,
            } => {
                let mut req = req.body_stream(stream);
                if let Some(len) = content_length {
                    let value = HeaderValue::from_str(&len.to_string())
                        .map_err(|_| Error::invalid_config("invalid Content-Length header"))?;
                    req = req.header(CONTENT_LENGTH, value);
                }
                req
            }
        };

        Ok(req)
    }
}

pub(crate) async fn response_error(resp: AsyncResponse) -> Error {
    let body_str = String::from_utf8_lossy(resp.body()).to_string();
    response_error_from_status(resp.status(), resp.headers(), &body_str)
}

fn ensure_empty_body(body: &AsyncBody) -> Result<()> {
    match body {
        AsyncBody::Empty => Ok(()),
        AsyncBody::Bytes(_) | AsyncBody::Stream { .. } => Err(Error::invalid_config(
            "this operation does not accept a request body",
        )),
    }
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

    #[tokio::test]
    async fn send_returns_response_for_http_error_status() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn send_head_with_content_encoding_and_empty_body_returns_ok() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::HEAD, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("zstd")
        );
        assert!(resp.body().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn send_stream_surfaces_embedded_service_error_on_2xx() -> Result<()> {
        let body = "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (addr, handle, hits) = spawn_test_server(vec![response.into_bytes()])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let stream = futures_util::stream::once(async { Ok(Bytes::from_static(b"hello")) });
        let err = transport
            .send(
                Method::PUT,
                url,
                HeaderMap::new(),
                AsyncBody::Stream {
                    stream: Box::pin(stream),
                    content_length: Some(5),
                },
            )
            .await
            .expect_err("expected embedded error xml to fail request");
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        match err {
            Error::Api {
                status,
                code,
                message,
                ..
            } => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(code.as_deref(), Some("AccessDenied"));
                assert_eq!(message.as_deref(), Some("denied"));
            }
            other => panic!("expected api error, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn response_error_extracts_rate_limit() -> Result<()> {
        let (addr, handle, _) = spawn_test_server(vec![
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nx-amz-request-id: req-1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        let err = response_error(resp).await;
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
        Ok(())
    }

    #[tokio::test]
    async fn response_error_parses_xml_error_fields() -> Result<()> {
        let body = r#"
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>req-inner</RequestId>
  <HostId>host-1</HostId>
</Error>
"#;
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nx-amz-request-id: req-outer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (addr, handle, _) = spawn_test_server(vec![response.into_bytes()])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        let err = response_error(resp).await;
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
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_on_retryable_status_for_replayable_body() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_does_not_retry_on_non_retryable_4xx_status() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_on_retryable_5xx_status() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_does_not_retry_on_retryable_status_for_non_idempotent_post() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(
                Method::POST,
                url,
                HeaderMap::new(),
                AsyncBody::Bytes(Bytes::from_static(b"hello")),
            )
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_on_transport_error_for_replayable_body() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_when_buffered_body_read_fails() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_on_embedded_retryable_service_error_xml() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_retries_on_retryable_service_error_code_from_4xx_body() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn send_stream_does_not_retry_for_non_replayable_body() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            max_retry_after: Duration::from_secs(30),
        };
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;
        let body = AsyncBody::Stream {
            stream: Box::pin(futures_util::stream::empty::<
                std::result::Result<Bytes, io::Error>,
            >()),
            content_length: Some(0),
        };

        let resp = transport
            .send_stream(Method::PUT, url, HeaderMap::new(), body)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        Ok(())
    }

    #[tokio::test]
    async fn send_rejects_body_for_get() -> Result<()> {
        let transport = AsyncTransport::new(
            RetryConfig::default(),
            None,
            Some(Duration::from_secs(1)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse("http://127.0.0.1:9/")
            .map_err(|_| Error::invalid_config("invalid test URL"))?;

        let err = transport
            .send(
                Method::GET,
                url,
                HeaderMap::new(),
                AsyncBody::Bytes(Bytes::from_static(b"body")),
            )
            .await
            .expect_err("GET body should be rejected");
        match err {
            Error::InvalidConfig { message } => {
                assert!(message.contains("does not accept a request body"));
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn send_stream_preserves_content_encoding_and_raw_bytes() -> Result<()> {
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
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send_stream(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );

        use http_body_util::BodyExt as _;
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| Error::transport("body stream error", Some(Box::new(e))))?;
            if let Some(data) = frame.data_ref() {
                out.extend_from_slice(data);
            }
        }

        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert_eq!(out, gzipped);
        Ok(())
    }

    #[tokio::test]
    async fn send_stream_body_read_error_is_observable() -> Result<()> {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc".to_vec();
        let (addr, handle, _) = spawn_test_server(vec![response])?;

        let retry = RetryConfig::default();
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send_stream(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        use http_body_util::BodyExt as _;
        let mut body = resp.into_body();
        let mut saw_error = false;
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                saw_error = true;
                break;
            }
        }
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert!(
            saw_error,
            "expected body stream error for truncated response"
        );
        Ok(())
    }

    #[tokio::test]
    async fn send_stream_into_response_limited_enforces_limit() -> Result<()> {
        let payload = "x".repeat(2048);
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        let (addr, handle, _) = spawn_test_server(vec![response.into_bytes()])?;

        let retry = RetryConfig::default();
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send_stream(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        let limited = resp.into_response_limited(1024).await;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;
        assert!(limited.is_err(), "expected body limit error");
        Ok(())
    }

    #[tokio::test]
    async fn send_does_not_follow_redirect_by_default() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig::default();
        let transport = AsyncTransport::new(
            retry,
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let resp = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await?;
        handle
            .join()
            .map_err(|_| Error::transport("test server thread panicked", None))?;

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        Ok(())
    }

    #[tokio::test]
    async fn send_does_not_succeed_after_query_only_redirect() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /?next=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let transport = AsyncTransport::new(
            RetryConfig::default(),
            None,
            Some(Duration::from_secs(5)),
            reqx::TlsRootStore::BackendDefault,
        )?;
        let url = Url::parse(&format!("http://{addr}/"))
            .map_err(|_| Error::invalid_config("invalid test server URL"))?;

        let outcome = transport
            .send(Method::GET, url, HeaderMap::new(), AsyncBody::Empty)
            .await;
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
        assert!(!followed_redirect(&request_url, request_url.as_str()));
        assert!(followed_redirect(&request_url, "not-a-valid-uri"));
    }
}
