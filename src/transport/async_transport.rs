use std::{
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};

#[cfg(feature = "metrics")]
use std::time::Instant;

use bytes::Bytes;
use futures_core::Stream;
use http::{HeaderMap, Method, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use url::Url;

use crate::{
    error::{Error, Result},
    transport::{RetryConfig, backoff_delay},
};

type AsyncByteStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, io::Error>> + Send + 'static>>;

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

struct SizedStreamBody {
    stream: Mutex<AsyncByteStream>,
    content_length: u64,
}

impl SizedStreamBody {
    fn new(stream: AsyncByteStream, content_length: u64) -> Self {
        Self {
            stream: Mutex::new(stream),
            content_length,
        }
    }
}

impl HttpBody for SizedStreamBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let mut stream = match this.stream.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Poll::Ready(Some(Err(io::Error::other("stream mutex poisoned"))));
            }
        };

        match stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.content_length)
    }
}

pub(crate) struct AsyncTransport {
    client: reqwest::Client,
    retry: RetryConfig,
}

impl AsyncTransport {
    pub(crate) fn new(
        retry: RetryConfig,
        user_agent: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        #[cfg(feature = "rustls")]
        crate::transport::tls::ensure_rustls_crypto_provider();

        let mut builder = reqwest::Client::builder();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        builder = builder.user_agent(user_agent.unwrap_or_else(default_user_agent));
        let client = builder
            .build()
            .map_err(|e| Error::transport("failed to build HTTP client", Some(Box::new(e))))?;

        Ok(Self { client, retry })
    }

    pub(crate) async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: AsyncBody,
    ) -> Result<reqwest::Response> {
        match body {
            body @ AsyncBody::Stream { .. } => {
                #[cfg(feature = "metrics")]
                metrics::counter!("s3_http_attempts_total", "method" => method_label(&method))
                    .increment(1);
                #[cfg(feature = "tracing")]
                let _guard = tracing::debug_span!(
                    "s3.http",
                    method = %method,
                    host = url.host_str().unwrap_or(""),
                    path = url.path(),
                    attempt = 1u32,
                )
                .entered();
                #[cfg(feature = "metrics")]
                let start = Instant::now();

                let req = self.build_request(&method, url, headers, body)?;
                match req.send().await {
                    Ok(resp) => {
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
                        Ok(resp)
                    }
                    Err(err) => {
                        #[cfg(feature = "metrics")]
                        metrics::counter!(
                            "s3_http_errors_total",
                            "method" => method_label(&method),
                            "kind" => "transport"
                        )
                        .increment(1);
                        Err(Error::transport("request failed", Some(Box::new(err))))
                    }
                }
            }
            replayable => {
                let max_attempts = if replayable.is_replayable() {
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

                    let current_body = replayable
                        .clone_for_retry()
                        .ok_or_else(|| Error::transport("request body is not replayable", None))?;
                    let req =
                        self.build_request(&method, url.clone(), headers.clone(), current_body)?;

                    match req.send().await {
                        Ok(resp) => {
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
                                let delay = retry_delay_from_response(self.retry, attempt, &resp);
                                drop(resp);
                                tokio::time::sleep(delay).await;
                                continue;
                            }
                            return Ok(resp);
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
                            return Err(Error::transport("request failed", Some(Box::new(err))));
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

    fn build_request(
        &self,
        method: &Method,
        url: Url,
        headers: HeaderMap,
        body: AsyncBody,
    ) -> Result<reqwest::RequestBuilder> {
        let mut req = self.client.request(method.clone(), url).headers(headers);
        req = match body {
            AsyncBody::Empty => req,
            AsyncBody::Bytes(b) => req.body(b),
            AsyncBody::Stream {
                stream,
                content_length,
            } => match content_length {
                Some(len) => req.body(reqwest::Body::wrap(SizedStreamBody::new(stream, len))),
                None => req.body(reqwest::Body::wrap_stream(stream)),
            },
        };
        Ok(req)
    }
}

pub(crate) async fn response_error(resp: reqwest::Response) -> Error {
    let status = resp.status();

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = resp
            .headers()
            .get(http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);

        return Error::RateLimited {
            retry_after,
            request_id,
        };
    }

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => Bytes::new(),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let snippet = crate::util::text::truncate_snippet(&body_str, 4096);

    if let Some(parsed) = crate::util::xml::parse_error_xml(&body_str) {
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
    resp: &reqwest::Response,
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

fn should_retry_error(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request() || err.is_body()
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

    #[tokio::test]
    async fn send_returns_response_for_http_error_status() -> Result<()> {
        let (addr, handle, hits) = spawn_test_server(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(retry, None, Some(Duration::from_secs(5)))?;
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
    async fn response_error_extracts_rate_limit() -> Result<()> {
        let (addr, handle, _) = spawn_test_server(vec![
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nx-amz-request-id: req-1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ])?;

        let retry = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        let transport = AsyncTransport::new(retry, None, Some(Duration::from_secs(5)))?;
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
        let transport = AsyncTransport::new(retry, None, Some(Duration::from_secs(5)))?;
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
        };
        let transport = AsyncTransport::new(retry, None, Some(Duration::from_secs(5)))?;
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
}
