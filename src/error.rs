use std::{error::Error as StdError, fmt, time::Duration};

use http::StatusCode;

pub type Result<T> = std::result::Result<T, Error>;

#[non_exhaustive]
pub enum Error {
    InvalidConfig {
        message: String,
    },

    Signing {
        message: String,
    },

    RateLimited {
        retry_after: Option<Duration>,
        request_id: Option<String>,
    },

    Api {
        status: StatusCode,
        code: Option<String>,
        message: Option<String>,
        request_id: Option<String>,
        host_id: Option<String>,
        body_snippet: Option<String>,
    },

    Transport {
        message: String,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    },

    Decode {
        message: String,
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
            } => f
                .debug_struct("RateLimited")
                .field("retry_after", retry_after)
                .field("request_id", request_id)
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
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            message: message.into(),
        }
    }

    pub fn signing(message: impl Into<String>) -> Self {
        Self::Signing {
            message: message.into(),
        }
    }

    pub fn transport(
        message: impl Into<String>,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Self::Transport {
            message: message.into(),
            source,
        }
    }

    pub fn decode(
        message: impl Into<String>,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Self::Decode {
            message: message.into(),
            source,
        }
    }

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

    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } => true,
            Self::Api { status, .. } => status.is_server_error(),
            Self::Transport { .. } => true,
            Self::InvalidConfig { .. } | Self::Signing { .. } | Self::Decode { .. } => false,
        }
    }
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
            Self::RateLimited { retry_after, .. } => write!(
                f,
                "rate limited{}",
                Self::format_rate_limited_retry_after(retry_after)
            ),
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
