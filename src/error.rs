use std::{error::Error as StdError, fmt, time::Duration};

use http::StatusCode;

/// Library result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for request building, transport, and API responses.
#[non_exhaustive]
pub enum Error {
    /// Invalid configuration or parameters.
    InvalidConfig {
        /// Human-readable validation failure message.
        message: String,
    },

    /// Request signing failed.
    Signing {
        /// Human-readable signing failure message.
        message: String,
    },

    /// Request was throttled by the service.
    RateLimited {
        /// Suggested delay before retrying, usually derived from `Retry-After`.
        retry_after: Option<Duration>,
        /// Service request id, when present in headers or the error payload.
        request_id: Option<String>,
        /// Service-specific error code, when present.
        code: Option<String>,
        /// Service-provided error message, when present.
        message: Option<String>,
        /// Service host id, when present.
        host_id: Option<String>,
        /// Truncated response body captured for debugging.
        body_snippet: Option<String>,
    },

    /// Service returned an error response.
    Api {
        /// HTTP status returned by the service.
        status: StatusCode,
        /// Service-specific error code, when present.
        code: Option<String>,
        /// Service-provided error message, when present.
        message: Option<String>,
        /// Service request id, when present in headers or the error payload.
        request_id: Option<String>,
        /// Service host id, when present.
        host_id: Option<String>,
        /// Truncated response body captured for debugging.
        body_snippet: Option<String>,
    },

    /// Transport-level failure (HTTP client, IO, TLS).
    Transport {
        /// Human-readable transport failure message.
        message: String,
        /// Underlying transport error, if preserved.
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    },

    /// Response decode or parse failure.
    Decode {
        /// Human-readable decode failure message.
        message: String,
        /// Underlying decode error, if preserved.
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    },
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { message } => f
                .debug_struct("InvalidConfig")
                .field("message", message)
                .finish(),
            Self::Signing { message } => {
                f.debug_struct("Signing").field("message", message).finish()
            }
            Self::RateLimited {
                retry_after,
                request_id,
                code,
                message,
                host_id,
                body_snippet,
            } => f
                .debug_struct("RateLimited")
                .field("retry_after", retry_after)
                .field("request_id", request_id)
                .field("code", code)
                .field("message", message)
                .field("host_id", host_id)
                .field("body_snippet", body_snippet)
                .finish(),
            Self::Api {
                status,
                code,
                message,
                request_id,
                host_id,
                body_snippet,
            } => f
                .debug_struct("Api")
                .field("status", status)
                .field("code", code)
                .field("message", message)
                .field("request_id", request_id)
                .field("host_id", host_id)
                .field("body_snippet", body_snippet)
                .finish(),
            Self::Transport { message, source } => f
                .debug_struct("Transport")
                .field("message", message)
                .field("source", source)
                .finish(),
            Self::Decode { message, source } => f
                .debug_struct("Decode")
                .field("message", message)
                .field("source", source)
                .finish(),
        }
    }
}

impl Error {
    /// Creates an invalid configuration error.
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            message: message.into(),
        }
    }

    /// Creates a signing error.
    pub fn signing(message: impl Into<String>) -> Self {
        Self::Signing {
            message: message.into(),
        }
    }

    /// Creates a transport error with optional source.
    pub fn transport(
        message: impl Into<String>,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Self::Transport {
            message: message.into(),
            source,
        }
    }

    /// Creates a decode error with optional source.
    pub fn decode(
        message: impl Into<String>,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Self::Decode {
            message: message.into(),
            source,
        }
    }

    /// Returns an HTTP status when available.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } => Some(*status),
            Self::RateLimited { .. } => Some(StatusCode::TOO_MANY_REQUESTS),
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns the request id if reported by the service.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Api { request_id, .. } | Self::RateLimited { request_id, .. } => {
                request_id.as_deref()
            }
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns the service error code when available.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } | Self::RateLimited { code, .. } => code.as_deref(),
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns the service error message when available.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Api { message, .. } | Self::RateLimited { message, .. } => message.as_deref(),
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns the service host id when available.
    pub fn host_id(&self) -> Option<&str> {
        match self {
            Self::Api { host_id, .. } | Self::RateLimited { host_id, .. } => host_id.as_deref(),
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns a truncated response body snippet when available.
    pub fn body_snippet(&self) -> Option<&str> {
        match self {
            Self::Api { body_snippet, .. } | Self::RateLimited { body_snippet, .. } => {
                body_snippet.as_deref()
            }
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::Transport { .. }
            | Self::Decode { .. } => None,
        }
    }

    /// Returns true if the error is safe to retry.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { status, code, .. } => {
                status.is_server_error()
                    || code.as_deref().is_some_and(is_retryable_service_error_code)
            }
            Self::Transport { .. } => true,
            Self::InvalidConfig { .. } | Self::Signing { .. } | Self::Decode { .. } => false,
        }
    }
}

fn is_retryable_service_error_code(code: &str) -> bool {
    matches!(
        code,
        "RequestTimeout"
            | "RequestTimeoutException"
            | "Throttling"
            | "ThrottlingException"
            | "ThrottledException"
            | "TooManyRequestsException"
            | "RequestLimitExceeded"
            | "SlowDown"
            | "InternalError"
            | "InternalFailure"
            | "ServiceUnavailable"
    )
}

fn format_optional_field(label: &str, value: &Option<String>) -> String {
    match value.as_deref() {
        Some(v) if !v.is_empty() => format!(" {label}={v}"),
        _ => String::new(),
    }
}

fn format_optional_message(value: &Option<String>) -> String {
    match value.as_deref() {
        Some(v) if !v.is_empty() => format!(" ({v})"),
        _ => String::new(),
    }
}

impl Error {
    fn format_rate_limited_retry_after(retry_after: &Option<Duration>) -> String {
        match retry_after {
            Some(d) => format!(" (retry after {}s)", d.as_secs()),
            None => String::new(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { message } => write!(f, "invalid config: {message}"),
            Self::Signing { message } => write!(f, "signing error: {message}"),
            Self::RateLimited {
                retry_after,
                code,
                message,
                request_id,
                host_id,
                ..
            } => {
                let retry_after = Self::format_rate_limited_retry_after(retry_after);
                let code = format_optional_field("code", code);
                let request_id = format_optional_field("request_id", request_id);
                let host_id = format_optional_field("host_id", host_id);
                let msg = format_optional_message(message);
                write!(
                    f,
                    "rate limited{retry_after}{code}{request_id}{host_id}{msg}"
                )
            }
            Self::Api {
                status,
                code,
                message,
                request_id,
                ..
            } => {
                let code = format_optional_field("code", code);
                let request_id = format_optional_field("request_id", request_id);
                let msg = format_optional_message(message);
                write!(f, "api error: {status}{code}{request_id}{msg}")
            }
            Self::Transport { message, .. } => write!(f, "transport error: {message}"),
            Self::Decode { message, .. } => write!(f, "decode error: {message}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transport { source, .. } | Self::Decode { source, .. } => {
                source.as_deref().map(|e| e as &(dyn StdError + 'static))
            }
            Self::InvalidConfig { .. }
            | Self::Signing { .. }
            | Self::RateLimited { .. }
            | Self::Api { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_retryability_can_be_driven_by_service_code() {
        let err = Error::Api {
            status: StatusCode::OK,
            code: Some("InternalError".to_string()),
            message: Some("backend failure".to_string()),
            request_id: None,
            host_id: None,
            body_snippet: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_with_non_retryable_code_and_2xx_status_is_not_retryable() {
        let err = Error::Api {
            status: StatusCode::OK,
            code: Some("AccessDenied".to_string()),
            message: Some("denied".to_string()),
            request_id: None,
            host_id: None,
            body_snippet: None,
        };
        assert!(!err.is_retryable());
    }
}
