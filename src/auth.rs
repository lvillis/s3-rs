use std::fmt;

use crate::error::Error;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Region(String);

impl Region {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::invalid_config("region must not be empty"));
        }
        Ok(Self(value))
    }

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

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl Credentials {
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Result<Self, Error> {
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

    pub fn with_session_token(mut self, session_token: impl Into<String>) -> Result<Self, Error> {
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

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Auth {
    Anonymous,
    Static(Credentials),
}

impl Auth {
    pub fn from_env() -> Result<Self, Error> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| Error::invalid_config("missing AWS_ACCESS_KEY_ID"))?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| Error::invalid_config("missing AWS_SECRET_ACCESS_KEY"))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        let mut creds = Credentials::new(access_key_id, secret_access_key)?;
        if let Some(token) = session_token {
            creds = creds.with_session_token(token)?;
        }

        Ok(Self::Static(creds))
    }

    #[cfg(feature = "credentials-profile")]
    pub fn from_profile(profile: impl AsRef<str>) -> Result<Self, Error> {
        let creds = crate::credentials::profile::load_profile_credentials(profile.as_ref())?;
        Ok(Self::Static(creds))
    }

    #[cfg(feature = "credentials-profile")]
    pub fn from_profile_env() -> Result<Self, Error> {
        Self::from_profile(crate::credentials::profile::profile_from_env())
    }

    #[cfg(all(feature = "credentials-imds", feature = "async"))]
    pub async fn from_imds() -> Result<Self, Error> {
        let creds = crate::credentials::imds::load_async().await?;
        Ok(Self::Static(creds))
    }

    #[cfg(all(feature = "credentials-imds", feature = "blocking"))]
    pub fn from_imds_blocking() -> Result<Self, Error> {
        let creds = crate::credentials::imds::load_blocking()?;
        Ok(Self::Static(creds))
    }

    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self, Error> {
        let creds = crate::credentials::sts::assume_role_async(
            region,
            role_arn.into(),
            role_session_name.into(),
            source_credentials,
        )
        .await?;
        Ok(Self::Static(creds))
    }

    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_blocking(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self, Error> {
        let creds = crate::credentials::sts::assume_role_blocking(
            region,
            role_arn.into(),
            role_session_name.into(),
            source_credentials,
        )?;
        Ok(Self::Static(creds))
    }

    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn from_web_identity_env() -> Result<Self, Error> {
        let creds = crate::credentials::sts::assume_role_with_web_identity_env_async().await?;
        Ok(Self::Static(creds))
    }

    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn from_web_identity_env_blocking() -> Result<Self, Error> {
        let creds = crate::credentials::sts::assume_role_with_web_identity_env_blocking()?;
        Ok(Self::Static(creds))
    }

    pub(crate) fn credentials(&self) -> Option<&Credentials> {
        match self {
            Self::Anonymous => None,
            Self::Static(creds) => Some(creds),
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressingStyle {
    Auto,
    Path,
    VirtualHosted,
}
