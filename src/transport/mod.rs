use std::{
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(any(feature = "tracing", feature = "async", feature = "blocking"))]
const REDACTED_HOST: &str = "<redacted-host>";

#[cfg(feature = "async")]
pub(crate) mod async_transport;
#[cfg(feature = "blocking")]
pub(crate) mod blocking_transport;

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
use http::HeaderMap;
#[cfg(any(feature = "async", feature = "blocking"))]
use http::Method;
#[cfg(any(test, feature = "async", feature = "blocking"))]
use http::StatusCode;
#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
use reqx::{
    Error as ReqxError, ErrorCode as ReqxErrorCode,
    advanced::{Interceptor, Observer, RequestContext, RetryDecision},
};
#[cfg(any(feature = "async", feature = "blocking"))]
use reqx::{
    advanced::{BackoffSource, TlsBackend},
    prelude::RetryPolicy,
};
#[cfg(any(feature = "tracing", feature = "async", feature = "blocking"))]
use url::Url;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryConfig {
    pub(crate) max_attempts: u32,
    pub(crate) base_delay: Duration,
    pub(crate) max_delay: Duration,
    pub(crate) max_retry_after: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) const MAX_BUFFERED_RESPONSE_BODY_BYTES: usize = 32 * 1024 * 1024;

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) trait TransportRequestBody: Sized {
    fn is_empty(&self) -> bool;
    fn is_replayable(&self) -> bool;
    fn clone_for_retry(&self) -> Option<Self>;
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) struct RequestAttemptState<B> {
    max_attempts: u32,
    initial_body: Option<B>,
    replayable_body: Option<B>,
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl<B> RequestAttemptState<B>
where
    B: TransportRequestBody,
{
    pub(crate) fn new(retry: RetryConfig, body: B) -> Self {
        let max_attempts = if body.is_replayable() {
            retry.max_attempts
        } else {
            1
        };

        Self {
            max_attempts,
            replayable_body: body.clone_for_retry(),
            initial_body: Some(body),
        }
    }

    pub(crate) fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub(crate) fn next_body(&mut self) -> crate::error::Result<B> {
        if let Some(body) = self.initial_body.take() {
            return Ok(body);
        }

        self.replayable_body
            .as_ref()
            .and_then(TransportRequestBody::clone_for_retry)
            .ok_or_else(|| crate::error::Error::transport("request body is not replayable", None))
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn ensure_method_accepts_body<B>(method: &Method, body: &B) -> crate::error::Result<()>
where
    B: TransportRequestBody,
{
    if matches!(*method, Method::GET | Method::HEAD | Method::DELETE) && !body.is_empty() {
        return Err(crate::error::Error::invalid_config(
            "this operation does not accept a request body",
        ));
    }
    Ok(())
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn prepare_user_agent(
    user_agent: Option<String>,
) -> crate::error::Result<(String, http::HeaderValue)> {
    let user_agent_text = user_agent.unwrap_or_else(default_user_agent);
    let user_agent = http::HeaderValue::from_str(&user_agent_text)
        .map_err(|_| crate::error::Error::invalid_config("invalid User-Agent header"))?;
    Ok((user_agent_text, user_agent))
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

#[cfg(any(feature = "async", feature = "blocking"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReqxBackoffSource {
    config: RetryConfig,
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl BackoffSource for ReqxBackoffSource {
    fn backoff_for_retry(&self, _retry_policy: &RetryPolicy, attempt: usize) -> Duration {
        backoff_delay(self.config, attempt as u32)
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn reqx_backoff_source(config: RetryConfig) -> ReqxBackoffSource {
    ReqxBackoffSource { config }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn reqx_retry_policy(config: RetryConfig) -> RetryPolicy {
    let base_backoff = if config.base_delay.is_zero() {
        Duration::from_millis(1)
    } else {
        config.base_delay
    };
    let max_backoff = config.max_delay.max(config.max_retry_after);

    RetryPolicy::standard()
        .max_attempts(config.max_attempts as usize)
        .base_backoff(base_backoff)
        .max_backoff(max_backoff)
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn default_tls_backend() -> TlsBackend {
    #[cfg(feature = "rustls")]
    {
        return TlsBackend::RustlsRing;
    }
    #[cfg(all(not(feature = "rustls"), feature = "native-tls"))]
    {
        return TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    TlsBackend::RustlsRing
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn default_user_agent() -> String {
    format!("s3/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
#[derive(Debug, Default)]
pub(crate) struct TransportMetricsObserver;

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
impl Observer for TransportMetricsObserver {
    fn on_request_start(&self, context: &RequestContext) {
        metrics::counter!("s3_http_attempts_total", "method" => method_label(context.method()))
            .increment(1);
    }

    fn on_retry_scheduled(
        &self,
        context: &RequestContext,
        decision: &RetryDecision,
        _delay: Duration,
    ) {
        metrics::counter!(
            "s3_http_retries_total",
            "method" => method_label(context.method()),
            "reason" => retry_reason_label(decision),
        )
        .increment(1);
    }
}

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
#[derive(Debug, Default)]
pub(crate) struct TransportMetricsInterceptor;

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
impl Interceptor for TransportMetricsInterceptor {
    fn on_response(&self, context: &RequestContext, status: StatusCode, _headers: &HeaderMap) {
        metrics::counter!(
            "s3_http_responses_total",
            "method" => method_label(context.method()),
            "class" => status_class(status),
        )
        .increment(1);
    }

    fn on_error(&self, context: &RequestContext, error: &ReqxError) {
        metrics::counter!(
            "s3_http_errors_total",
            "method" => method_label(context.method()),
            "kind" => reqx_error_kind_label(error),
        )
        .increment(1);
    }
}

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
fn retry_reason_label(decision: &RetryDecision) -> &'static str {
    if decision.status().is_some() {
        "status"
    } else if decision.transport_error_kind().is_some()
        || decision.timeout_phase().is_some()
        || decision.is_response_body_read_error()
    {
        "transport"
    } else {
        "other"
    }
}

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
fn reqx_error_kind_label(error: &ReqxError) -> &'static str {
    match error.code() {
        ReqxErrorCode::MissingRedirectLocation
        | ReqxErrorCode::InvalidRedirectLocation
        | ReqxErrorCode::RedirectLimitExceeded
        | ReqxErrorCode::RedirectBodyNotReplayable => "redirect",
        _ => "transport",
    }
}

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
pub(crate) fn status_class(status: StatusCode) -> &'static str {
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

#[cfg(all(feature = "metrics", any(feature = "async", feature = "blocking")))]
pub(crate) fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "PUT" => "PUT",
        "HEAD" => "HEAD",
        "DELETE" => "DELETE",
        "POST" => "POST",
        _ => "OTHER",
    }
}

fn jitter_millis(max_millis: u128) -> u128 {
    if max_millis <= 1 {
        return max_millis;
    }

    u128::from(next_jitter_u64()) % max_millis
}

fn next_jitter_u64() -> u64 {
    static JITTER_STATE: OnceLock<AtomicU64> = OnceLock::new();
    let state = JITTER_STATE.get_or_init(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ u64::from(std::process::id());
        AtomicU64::new(seed.max(1))
    });

    let mut current = state.load(Ordering::Relaxed);
    loop {
        let next = current.wrapping_mul(6364136223846793005).wrapping_add(1);
        match state.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
fn request_id_from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("x-amz-request-id")
        .or_else(|| headers.get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) fn retry_after_from_headers(headers: &http::HeaderMap) -> Option<Duration> {
    headers
        .get(http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_value)
}

#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) fn clamp_retry_after(config: RetryConfig, retry_after: Duration) -> Duration {
    retry_after.min(config.max_retry_after)
}

#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) fn retry_delay_from_response(
    config: RetryConfig,
    attempt: u32,
    status: StatusCode,
    headers: &http::HeaderMap,
) -> Duration {
    if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
        && let Some(retry_after) = retry_after_from_headers(headers)
    {
        return clamp_retry_after(config, retry_after);
    }
    backoff_delay(config, attempt)
}

#[cfg(any(test, feature = "async", feature = "blocking"))]
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
pub(crate) struct RequestTimer {
    #[cfg(feature = "metrics")]
    start: std::time::Instant,
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl RequestTimer {
    pub(crate) fn start() -> Self {
        Self {
            #[cfg(feature = "metrics")]
            start: std::time::Instant::now(),
        }
    }

    pub(crate) fn finish(&self, method: &Method) {
        #[cfg(feature = "metrics")]
        metrics::histogram!(
            "s3_http_request_duration_seconds",
            "method" => method_label(method),
        )
        .record(self.start.elapsed().as_secs_f64());

        #[cfg(not(feature = "metrics"))]
        let _ = method;
    }

    pub(crate) fn finish_service_error(&self, method: &Method) {
        #[cfg(feature = "metrics")]
        {
            metrics::counter!(
                "s3_http_errors_total",
                "method" => method_label(method),
                "kind" => "service"
            )
            .increment(1);
            self.finish(method);
        }

        #[cfg(not(feature = "metrics"))]
        let _ = method;
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn record_service_retry(method: &Method) {
    #[cfg(feature = "metrics")]
    metrics::counter!(
        "s3_http_retries_total",
        "method" => method_label(method),
        "reason" => "service"
    )
    .increment(1);

    #[cfg(not(feature = "metrics"))]
    let _ = method;
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn response_error_from_status(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &str,
) -> crate::error::Error {
    let request_id = request_id_from_headers(headers);
    let parsed = crate::util::xml::parse_error_xml(body);
    let snippet = crate::util::text::truncate_snippet(body, 4096);

    if status == http::StatusCode::TOO_MANY_REQUESTS {
        if let Some(parsed) = parsed {
            return crate::error::Error::RateLimited {
                retry_after: retry_after_from_headers(headers),
                request_id: parsed.request_id.or(request_id),
                code: parsed.code,
                message: parsed.message,
                host_id: parsed.host_id,
                body_snippet: Some(snippet),
            };
        }

        return crate::error::Error::RateLimited {
            retry_after: retry_after_from_headers(headers),
            request_id,
            code: None,
            message: None,
            host_id: None,
            body_snippet: Some(snippet),
        };
    }

    if let Some(parsed) = parsed {
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
pub(crate) enum ServiceErrorAction {
    RetryAfter(Duration),
    ReturnErr(crate::error::Error),
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn service_error_action(
    retry: RetryConfig,
    attempt: u32,
    max_attempts: u32,
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body: &str,
) -> Option<ServiceErrorAction> {
    let err = response_service_error(status, headers, body)?;

    if attempt < max_attempts && err.is_retryable() {
        return Some(ServiceErrorAction::RetryAfter(retry_delay_from_response(
            retry, attempt, status, headers,
        )));
    }

    if status.is_success() {
        return Some(ServiceErrorAction::ReturnErr(err));
    }

    None
}

#[cfg(any(feature = "async", feature = "blocking"))]
struct SanitizedReqxSource {
    code: reqx::ErrorCode,
    method: Option<http::Method>,
    uri: Option<String>,
    detail: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl SanitizedReqxSource {
    fn new(
        code: reqx::ErrorCode,
        method: Option<http::Method>,
        uri: Option<String>,
        detail: Option<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            code,
            method,
            uri,
            detail,
            source,
        }
    }

    fn with_uri(uri: String) -> Option<String> {
        Some(redacted_uri_for_error(&uri))
    }

    fn from_reqx(error: reqx::Error) -> Self {
        let fallback_code = error.code();
        let fallback_method = error.request_method().cloned();
        let fallback_uri = error
            .request_uri_redacted_owned()
            .map(|uri| redacted_uri_for_error(&uri));

        match error {
            reqx::Error::InvalidUri { uri } => Self::new(
                reqx::ErrorCode::InvalidUri,
                None,
                Self::with_uri(uri),
                None,
                None,
            ),
            reqx::Error::InvalidNoProxyRule { rule } => Self::new(
                reqx::ErrorCode::InvalidNoProxyRule,
                None,
                None,
                Some(format!("rule={rule:?}")),
                None,
            ),
            reqx::Error::InvalidProxyConfig { proxy_uri, message } => Self::new(
                reqx::ErrorCode::InvalidProxyConfig,
                None,
                Self::with_uri(proxy_uri),
                Some(message),
                None,
            ),
            reqx::Error::ProxyAuthorizationRequiresHttpProxy => Self::new(
                reqx::ErrorCode::InvalidProxyConfig,
                None,
                None,
                Some("proxy_authorization requires http_proxy".to_string()),
                None,
            ),
            reqx::Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit,
                initial_limit,
                max_limit,
                message,
            } => Self::new(
                reqx::ErrorCode::InvalidAdaptiveConcurrencyPolicy,
                None,
                None,
                Some(format!(
                    "min_limit={min_limit} initial_limit={initial_limit} max_limit={max_limit}: {message}"
                )),
                None,
            ),
            reqx::Error::SerializeJson { source } => Self::new(
                reqx::ErrorCode::SerializeJson,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::SerializeQuery { source } => Self::new(
                reqx::ErrorCode::SerializeQuery,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::SerializeForm { source } => Self::new(
                reqx::ErrorCode::SerializeForm,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::RequestBuild { source } => Self::new(
                reqx::ErrorCode::RequestBuild,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::Transport {
                kind,
                method,
                uri,
                source,
            } => Self::new(
                reqx::ErrorCode::Transport,
                Some(method),
                Self::with_uri(uri),
                Some(format!("kind={kind}")),
                Some(source),
            ),
            reqx::Error::Timeout {
                phase,
                timeout_ms,
                method,
                uri,
            } => Self::new(
                reqx::ErrorCode::Timeout,
                Some(method),
                Self::with_uri(uri),
                Some(format!("phase={phase} timeout_ms={timeout_ms}")),
                None,
            ),
            reqx::Error::DeadlineExceeded {
                timeout_ms,
                method,
                uri,
            } => Self::new(
                reqx::ErrorCode::DeadlineExceeded,
                Some(method),
                Self::with_uri(uri),
                Some(format!("timeout_ms={timeout_ms}")),
                None,
            ),
            reqx::Error::ReadBody { source } => {
                Self::new(reqx::ErrorCode::ReadBody, None, None, None, Some(source))
            }
            reqx::Error::ResponseBodyTooLarge {
                limit_bytes,
                actual_bytes,
                method,
                uri,
            } => Self::new(
                reqx::ErrorCode::ResponseBodyTooLarge,
                Some(method),
                Self::with_uri(uri),
                Some(format!(
                    "actual_bytes={actual_bytes} limit_bytes={limit_bytes}"
                )),
                None,
            ),
            reqx::Error::HttpStatus {
                status,
                method,
                uri,
                ..
            } => Self::new(
                reqx::ErrorCode::HttpStatus,
                Some(method),
                Self::with_uri(uri),
                Some(format!("status={status}")),
                None,
            ),
            reqx::Error::DeserializeJson { source, .. } => Self::new(
                reqx::ErrorCode::DeserializeJson,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::DecodeText { source, .. } => Self::new(
                reqx::ErrorCode::DecodeText,
                None,
                None,
                None,
                Some(Box::new(source)),
            ),
            reqx::Error::InvalidHeaderName { name, source } => Self::new(
                reqx::ErrorCode::InvalidHeaderName,
                None,
                None,
                Some(format!("name={name}")),
                Some(Box::new(source)),
            ),
            reqx::Error::InvalidHeaderValue { name, source } => Self::new(
                reqx::ErrorCode::InvalidHeaderValue,
                None,
                None,
                Some(format!("name={name}")),
                Some(Box::new(source)),
            ),
            reqx::Error::DecodeContentEncoding {
                encoding,
                method,
                uri,
                message,
            } => Self::new(
                reqx::ErrorCode::DecodeContentEncoding,
                Some(method),
                Self::with_uri(uri),
                Some(format!("encoding={encoding}: {message}")),
                None,
            ),
            reqx::Error::ConcurrencyLimitClosed => Self::new(
                reqx::ErrorCode::ConcurrencyLimitClosed,
                None,
                None,
                None,
                None,
            ),
            reqx::Error::TlsBackendUnavailable { backend } => Self::new(
                reqx::ErrorCode::TlsBackendUnavailable,
                None,
                None,
                Some(format!("backend={backend}")),
                None,
            ),
            reqx::Error::TlsBackendInit { backend, message } => Self::new(
                reqx::ErrorCode::TlsBackendInit,
                None,
                None,
                Some(format!("backend={backend}: {message}")),
                None,
            ),
            reqx::Error::TlsConfig { backend, message } => Self::new(
                reqx::ErrorCode::TlsConfig,
                None,
                None,
                Some(format!("backend={backend}: {message}")),
                None,
            ),
            reqx::Error::RetryBudgetExhausted { method, uri } => Self::new(
                reqx::ErrorCode::RetryBudgetExhausted,
                Some(method),
                Self::with_uri(uri),
                None,
                None,
            ),
            reqx::Error::CircuitOpen {
                method,
                uri,
                retry_after_ms,
            } => Self::new(
                reqx::ErrorCode::CircuitOpen,
                Some(method),
                Self::with_uri(uri),
                Some(format!("retry_after_ms={retry_after_ms}")),
                None,
            ),
            reqx::Error::MissingRedirectLocation {
                status,
                method,
                uri,
            } => Self::new(
                reqx::ErrorCode::MissingRedirectLocation,
                Some(method),
                Self::with_uri(uri),
                Some(format!("status={status}")),
                None,
            ),
            reqx::Error::InvalidRedirectLocation { method, uri, .. } => Self::new(
                reqx::ErrorCode::InvalidRedirectLocation,
                Some(method),
                Self::with_uri(uri),
                None,
                None,
            ),
            reqx::Error::RedirectLimitExceeded {
                max_redirects,
                method,
                uri,
            } => Self::new(
                reqx::ErrorCode::RedirectLimitExceeded,
                Some(method),
                Self::with_uri(uri),
                Some(format!("max_redirects={max_redirects}")),
                None,
            ),
            reqx::Error::RedirectBodyNotReplayable { method, uri } => Self::new(
                reqx::ErrorCode::RedirectBodyNotReplayable,
                Some(method),
                Self::with_uri(uri),
                None,
                None,
            ),
            _ => Self::new(fallback_code, fallback_method, fallback_uri, None, None),
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl std::fmt::Display for SanitizedReqxSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "reqx {}", self.code.as_str())?;
        if let Some(method) = &self.method {
            write!(formatter, " for {method}")?;
        }
        if let Some(uri) = &self.uri {
            write!(formatter, " {uri}")?;
        }
        if let Some(detail) = &self.detail {
            write!(formatter, " ({detail})")?;
        }
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl std::fmt::Debug for SanitizedReqxSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SanitizedReqxSource")
            .field("message", &self.to_string())
            .finish()
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl std::error::Error for SanitizedReqxSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|error| error as _)
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
fn redacted_uri_for_error(uri: &str) -> String {
    match Url::parse(uri) {
        Ok(url) => redacted_url_for_error(&url),
        Err(_) => "<redacted-uri>".to_string(),
    }
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
        other => crate::error::Error::transport(
            message,
            Some(Box::new(SanitizedReqxSource::from_reqx(other))),
        ),
    }
}

#[cfg(all(test, any(feature = "async", feature = "blocking")))]
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

#[cfg(all(test, any(feature = "async", feature = "blocking")))]
pub(crate) fn unexpected_redirect_error(
    method: &Method,
    request_url: &Url,
    response_uri: &str,
) -> crate::error::Error {
    let request = redacted_url_for_error(request_url);
    let response = redacted_response_uri_for_error(response_uri);
    crate::error::Error::transport(
        format!("unexpected redirect followed for {method} {request} -> {response}",),
        None,
    )
}

#[cfg(all(test, any(feature = "async", feature = "blocking")))]
fn redacted_response_uri_for_error(response_uri: &str) -> String {
    match Url::parse(response_uri) {
        Ok(url) => redacted_url_for_error(&url),
        Err(_) => "<unparseable-uri>".to_string(),
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
pub(crate) fn redacted_url_for_error(url: &Url) -> String {
    let mut out = String::new();
    out.push_str(url.scheme());
    out.push_str("://");
    out.push_str(REDACTED_HOST);

    if let Some(port) = url.port() {
        let default = match url.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        if Some(port) != default {
            out.push(':');
            out.push_str(&port.to_string());
        }
    }

    out.push_str(redacted_path_for_trace(url));
    if url.query().is_some() {
        out.push_str("?<redacted>");
    }
    out
}

#[cfg(all(test, any(feature = "async", feature = "blocking")))]
pub(crate) fn redacted_request_context(method: &Method, url: &Url) -> String {
    format!("{method} {}", redacted_url_for_error(url))
}

#[cfg(any(feature = "tracing", feature = "async", feature = "blocking"))]
pub(crate) fn redacted_path_for_trace(url: &Url) -> &'static str {
    if url.path() == "/" {
        "/"
    } else {
        "/<redacted>"
    }
}

#[cfg(all(
    any(feature = "async", feature = "blocking"),
    any(feature = "tracing", test)
))]
pub(crate) fn redacted_host_for_trace(_url: &Url) -> &'static str {
    REDACTED_HOST
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[cfg(any(feature = "async", feature = "blocking"))]
    use http::Method;

    use super::*;

    #[test]
    fn backoff_delay_is_capped_and_non_negative() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
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
            max_retry_after: Duration::from_secs(30),
        };

        assert_eq!(backoff_delay(cfg, 1), Duration::from_millis(0));
        assert_eq!(backoff_delay(cfg, 10), Duration::from_millis(0));
    }

    #[test]
    fn retry_config_default_includes_retry_budget() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.max_retry_after, Duration::from_secs(30));
    }

    #[test]
    fn jitter_millis_produces_varying_values() {
        let mut seen = BTreeSet::new();
        for _ in 0..16 {
            seen.insert(jitter_millis(997));
        }
        assert!(seen.len() > 1);
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
    fn map_reqx_error_transport_source_redacts_host_path_and_query() {
        let err = reqx::Error::Transport {
            kind: reqx::TransportErrorKind::Connect,
            method: http::Method::GET,
            uri: "https://bucket.s3.example.com/private/object/key?token=secret".to_string(),
            source: Box::new(std::io::Error::other("connect failed")),
        };

        let mapped = map_reqx_error("request failed", err);
        let debug = format!("{mapped:?}");

        match mapped {
            crate::error::Error::Transport { message, source } => {
                assert_eq!(message, "request failed");
                let source = source.expect("expected sanitized reqx source");
                let source_text = source.to_string();

                assert!(source_text.contains("https://<redacted-host>/<redacted>"));
                assert!(!source_text.contains("bucket.s3.example.com"));
                assert!(!source_text.contains("private/object/key"));
                assert!(!source_text.contains("token=secret"));

                assert!(debug.contains("https://<redacted-host>/<redacted>"));
                assert!(!debug.contains("bucket.s3.example.com"));
                assert!(!debug.contains("private/object/key"));
                assert!(!debug.contains("token=secret"));
            }
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

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

    #[test]
    fn clamp_retry_after_respects_retry_policy_cap() {
        let config = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
        };

        assert_eq!(
            clamp_retry_after(config, Duration::from_millis(500)),
            Duration::from_millis(500)
        );
        assert_eq!(
            clamp_retry_after(config, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            clamp_retry_after(config, Duration::from_secs(60)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn retry_delay_from_response_uses_retry_after_for_503() {
        let config = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
            max_retry_after: Duration::from_secs(30),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("5"),
        );

        assert_eq!(
            retry_delay_from_response(config, 1, http::StatusCode::SERVICE_UNAVAILABLE, &headers),
            Duration::from_secs(5)
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
                code,
                message,
                host_id,
                ..
            } => {
                assert_eq!(retry_after, Some(Duration::from_secs(3)));
                assert_eq!(request_id.as_deref(), Some("req-matrix"));
                assert!(code.is_none());
                assert!(message.is_none());
                assert!(host_id.is_none());
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
    fn unexpected_redirect_error_redacts_query_values() {
        let request_url = Url::parse(
            "https://example.com/path?X-Amz-Credential=AKIA&X-Amz-Signature=super-secret",
        )
        .expect("valid URL");
        let response_uri = "https://example.com/path?token=secret-token";
        let err = unexpected_redirect_error(&Method::GET, &request_url, response_uri);

        match err {
            crate::error::Error::Transport { message, .. } => {
                assert!(message.contains("https://<redacted-host>/<redacted>?<redacted>"));
                assert!(message.contains("-> https://<redacted-host>/<redacted>?<redacted>"));
                assert!(!message.contains("example.com"));
                assert!(!message.contains("/path"));
                assert!(!message.contains("X-Amz-Credential"));
                assert!(!message.contains("X-Amz-Signature"));
                assert!(!message.contains("secret-token"));
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn unexpected_redirect_error_hides_unparseable_uri_contents() {
        let request_url =
            Url::parse("https://example.com/path?X-Amz-Signature=super-secret").expect("valid URL");
        let err = unexpected_redirect_error(&Method::GET, &request_url, "%%%bad uri%%%");
        match err {
            crate::error::Error::Transport { message, .. } => {
                assert!(message.contains("<unparseable-uri>"));
                assert!(!message.contains("%%%bad uri%%%"));
                assert!(!message.contains("super-secret"));
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn redacted_request_context_hides_path_and_query() {
        let url = Url::parse("https://example.com/private/key/path?token=secret").expect("url");
        let ctx = redacted_request_context(&Method::GET, &url);
        assert!(ctx.contains("GET https://<redacted-host>/<redacted>?<redacted>"));
        assert!(!ctx.contains("example.com"));
        assert!(!ctx.contains("private/key/path"));
        assert!(!ctx.contains("token=secret"));
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn redacted_path_for_trace_hides_object_paths() {
        let root = Url::parse("https://example.com/").expect("url");
        let object = Url::parse("https://example.com/a/b/c?token=secret").expect("url");
        assert_eq!(redacted_path_for_trace(&root), "/");
        assert_eq!(redacted_path_for_trace(&object), "/<redacted>");
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn redacted_host_for_trace_hides_virtual_host_bucket() {
        let url = Url::parse("https://bucket-with-sensitive-name.s3.example.com/key").expect("url");
        assert_eq!(redacted_host_for_trace(&url), "<redacted-host>");
    }

    #[cfg(any(feature = "async", feature = "blocking"))]
    #[test]
    fn response_error_from_status_429_preserves_service_error_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-request-id",
            http::HeaderValue::from_static("req-outer"),
        );

        let body = r#"
<Error>
  <Code>SlowDown</Code>
  <Message>slow down</Message>
  <RequestId>req-inner</RequestId>
  <HostId>host-1</HostId>
</Error>
"#;

        match response_error_from_status(http::StatusCode::TOO_MANY_REQUESTS, &headers, body) {
            crate::error::Error::RateLimited {
                request_id,
                code,
                message,
                host_id,
                body_snippet,
                ..
            } => {
                assert_eq!(request_id.as_deref(), Some("req-inner"));
                assert_eq!(code.as_deref(), Some("SlowDown"));
                assert_eq!(message.as_deref(), Some("slow down"));
                assert_eq!(host_id.as_deref(), Some("host-1"));
                assert!(
                    body_snippet
                        .as_deref()
                        .unwrap_or_default()
                        .contains("SlowDown")
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
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
    fn response_service_error_maps_request_id_only_error_payload() {
        let body = r#"<Error><RequestId>req-only</RequestId></Error>"#;
        let err =
            response_service_error(http::StatusCode::BAD_REQUEST, &http::HeaderMap::new(), body)
                .expect("request-id-only payload should be treated as service error");
        match err {
            crate::error::Error::Api {
                status, request_id, ..
            } => {
                assert_eq!(status, http::StatusCode::BAD_REQUEST);
                assert_eq!(request_id.as_deref(), Some("req-only"));
            }
            other => panic!("expected Api error, got {other:?}"),
        }
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
