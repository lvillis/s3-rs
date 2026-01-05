use std::{io, pin::Pin, time::Duration};

#[cfg(feature = "metrics")]
use std::time::Instant;

use bytes::Bytes;
use futures_core::Stream;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::{
    error::{Error, Result},
    transport::{RetryConfig, backoff_delay},
};

pub(crate) enum AsyncBody {
    Empty,
    Bytes(Bytes),
    Stream(Pin<Box<dyn Stream<Item = std::result::Result<Bytes, io::Error>> + Send + 'static>>),
}

impl AsyncBody {
    fn is_replayable(&self) -> bool {
        matches!(self, Self::Empty | Self::Bytes(_))
    }

    fn clone_for_retry(&self) -> Option<Self> {
        match self {
            Self::Empty => Some(Self::Empty),
            Self::Bytes(b) => Some(Self::Bytes(b.clone())),
            Self::Stream(_) => None,
        }
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
            AsyncBody::Stream(stream) => {
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

                let req = self.build_request(&method, url, headers, AsyncBody::Stream(stream))?;
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
            AsyncBody::Stream(s) => req.body(reqwest::Body::wrap_stream(s)),
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
