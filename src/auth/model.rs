use std::fmt;

use time::OffsetDateTime;

use crate::{Error, Result};

use super::DynCredentialsProvider;

/// Snapshot of credentials and optional expiration metadata.
#[derive(Clone, Debug)]
pub struct CredentialsSnapshot {
    credentials: Credentials,
    expires_at: Option<OffsetDateTime>,
}

impl CredentialsSnapshot {
    /// Creates a snapshot without an expiration time.
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            expires_at: None,
        }
    }

    /// Sets the expiration time for this snapshot.
    pub fn with_expires_at(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Returns the credential material.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Returns the expiration time if known.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
}

/// Region identifier used for signing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Region(String);

impl Region {
    /// Creates a region from a non-empty string.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::invalid_config("region must not be empty"));
        }
        Ok(Self(value))
    }

    /// Returns the region string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Region").field(&self.0).finish()
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Region {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Static access credentials with optional session token.
#[derive(Clone)]
pub struct Credentials {
    /// Access key identifier.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
    /// Optional session token for temporary credentials.
    pub session_token: Option<String>,
}

impl Credentials {
    /// Creates credentials from access and secret keys.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Result<Self> {
        let access_key_id = access_key_id.into();
        let secret_access_key = secret_access_key.into();

        if access_key_id.trim().is_empty() {
            return Err(Error::invalid_config("access_key_id must not be empty"));
        }
        if secret_access_key.trim().is_empty() {
            return Err(Error::invalid_config("secret_access_key must not be empty"));
        }

        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token: None,
        })
    }

    /// Attaches a session token for temporary credentials.
    pub fn with_session_token(mut self, session_token: impl Into<String>) -> Result<Self> {
        let session_token = session_token.into();
        if session_token.trim().is_empty() {
            return Err(Error::invalid_config("session_token must not be empty"));
        }
        self.session_token = Some(session_token);
        Ok(self)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field(
                "access_key_id",
                &crate::util::redact::redact_value(&self.access_key_id),
            )
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self
                    .session_token
                    .as_ref()
                    .map(|v| crate::util::redact::redact_value(v)),
            )
            .finish()
    }
}

/// Authentication configuration for requests.
///
/// Most applications use one of the constructor helpers on [`Auth`]:
///
/// - [`Auth::from_env`] for static credentials from environment variables
/// - [`Auth::provider`] for a custom refreshable provider
/// - [`Auth::Anonymous`] for unsigned requests
///
/// Optional credential features also add profile, IMDS, and STS-based constructors.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Auth {
    /// Send unsigned requests.
    Anonymous,
    /// Static access keys (and optional session token).
    Static(Credentials),
    /// Dynamic credentials provider.
    Provider(DynCredentialsProvider),
}

/// How the bucket name is encoded into the request URL.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressingStyle {
    /// Automatically choose virtual-hosted vs path style.
    Auto,
    /// Always use path-style URLs.
    Path,
    /// Always use virtual-hosted-style URLs.
    VirtualHosted,
}
