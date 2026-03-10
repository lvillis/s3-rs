use std::sync::Arc;

#[cfg(feature = "async")]
use std::{future::Future, pin::Pin};

#[cfg(all(
    any(feature = "async", feature = "blocking"),
    any(feature = "credentials-imds", feature = "credentials-sts")
))]
use reqx::advanced::TlsRootStore;

use crate::{Error, Result};

use super::{Auth, Credentials};

#[cfg(any(feature = "async", feature = "blocking"))]
use super::CredentialsSnapshot;
#[cfg(feature = "credentials-sts")]
use super::Region;
#[cfg(any(feature = "credentials-imds", feature = "credentials-sts"))]
use super::cache::CachedProvider;

#[cfg(feature = "async")]
/// Async credentials lookup future.
pub type CredentialsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CredentialsSnapshot>> + Send + 'a>>;

/// Source of credential snapshots for request signing.
///
/// Implement this trait when credentials may rotate over time. If the underlying provider performs
/// network calls or expensive refreshes, wrap it in [`crate::CachedProvider`] so multiple requests
/// can share cached credentials and coalesce refresh work.
pub trait CredentialsProvider: std::fmt::Debug + Send + Sync {
    /// Returns credentials asynchronously.
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_>;

    /// Returns credentials in blocking mode.
    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot>;
}

/// Shared credentials provider trait object.
pub type DynCredentialsProvider = Arc<dyn CredentialsProvider>;

/// Trust root selection for credential-provider HTTPS requests (IMDS/STS).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CredentialsTlsRootStore {
    /// Use the backend default trust roots.
    ///
    /// For `rustls`, this maps to WebPKI roots.
    /// For `native-tls`, this follows backend default behavior.
    #[default]
    BackendDefault,
    /// Force WebPKI roots.
    WebPki,
    /// Use platform/system trust verification.
    System,
}

impl CredentialsTlsRootStore {
    #[cfg(all(
        any(feature = "async", feature = "blocking"),
        any(feature = "credentials-imds", feature = "credentials-sts")
    ))]
    pub(crate) const fn into_reqx(self) -> TlsRootStore {
        match self {
            Self::BackendDefault => TlsRootStore::BackendDefault,
            Self::WebPki => TlsRootStore::WebPki,
            Self::System => TlsRootStore::System,
        }
    }
}

#[cfg(feature = "credentials-sts")]
#[derive(Clone, Debug)]
struct StaticCredentialsProvider {
    snapshot: CredentialsSnapshot,
}

#[cfg(feature = "credentials-sts")]
impl StaticCredentialsProvider {
    fn new(credentials: Credentials) -> Self {
        Self {
            snapshot: CredentialsSnapshot::new(credentials),
        }
    }
}

#[cfg(feature = "credentials-sts")]
impl CredentialsProvider for StaticCredentialsProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        let snapshot = self.snapshot.clone();
        Box::pin(async move { Ok(snapshot) })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        Ok(self.snapshot.clone())
    }
}

#[cfg(feature = "credentials-imds")]
#[derive(Debug, Clone, Copy)]
struct ImdsProvider {
    tls_root_store: CredentialsTlsRootStore,
}

#[cfg(feature = "credentials-imds")]
impl CredentialsProvider for ImdsProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(async move {
            crate::credentials::imds::load_async(self.tls_root_store.into_reqx()).await
        })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        crate::credentials::imds::load_blocking(self.tls_root_store.into_reqx())
    }
}

#[cfg(feature = "credentials-sts")]
#[derive(Debug)]
struct StsAssumeRoleProvider {
    region: Region,
    role_arn: String,
    role_session_name: String,
    source: DynCredentialsProvider,
    tls_root_store: CredentialsTlsRootStore,
}

#[cfg(feature = "credentials-sts")]
impl CredentialsProvider for StsAssumeRoleProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(async move {
            let source = self.source.credentials_async().await?;
            crate::credentials::sts::assume_role_async(
                self.region.clone(),
                self.role_arn.clone(),
                self.role_session_name.clone(),
                source.credentials().clone(),
                self.tls_root_store.into_reqx(),
            )
            .await
        })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        let source = self.source.credentials_blocking()?;
        crate::credentials::sts::assume_role_blocking(
            self.region.clone(),
            self.role_arn.clone(),
            self.role_session_name.clone(),
            source.credentials().clone(),
            self.tls_root_store.into_reqx(),
        )
    }
}

#[cfg(feature = "credentials-sts")]
#[derive(Debug, Clone, Copy)]
struct StsWebIdentityProvider {
    tls_root_store: CredentialsTlsRootStore,
}

#[cfg(feature = "credentials-sts")]
impl CredentialsProvider for StsWebIdentityProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(async move {
            crate::credentials::sts::assume_role_with_web_identity_env_async(
                self.tls_root_store.into_reqx(),
            )
            .await
        })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        crate::credentials::sts::assume_role_with_web_identity_env_blocking(
            self.tls_root_store.into_reqx(),
        )
    }
}

impl Auth {
    /// Loads static credentials from standard AWS env vars.
    ///
    /// Reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`.
    pub fn from_env() -> Result<Self> {
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

    /// Uses a dynamic credentials provider.
    pub fn provider(provider: DynCredentialsProvider) -> Self {
        Self::Provider(provider)
    }

    /// Loads credentials from a named profile.
    #[cfg(feature = "credentials-profile")]
    pub fn from_profile(profile: impl AsRef<str>) -> Result<Self> {
        let creds = crate::credentials::profile::load_profile_credentials(profile.as_ref())?;
        Ok(Self::Static(creds))
    }

    /// Loads credentials from the profile defined by environment variables.
    #[cfg(feature = "credentials-profile")]
    pub fn from_profile_env() -> Result<Self> {
        Self::from_profile(crate::credentials::profile::profile_from_env())
    }

    /// Loads IMDS credentials and wraps them in a cached provider.
    #[cfg(all(feature = "credentials-imds", feature = "async"))]
    pub async fn from_imds() -> Result<Self> {
        Self::from_imds_with_tls_root_store(CredentialsTlsRootStore::BackendDefault).await
    }

    /// Loads IMDS credentials and wraps them in a cached provider.
    #[cfg(all(feature = "credentials-imds", feature = "async"))]
    pub async fn from_imds_with_tls_root_store(
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let initial = crate::credentials::imds::load_async(tls_root_store.into_reqx()).await?;
        let provider = CachedProvider::new(ImdsProvider { tls_root_store }).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    /// Loads IMDS credentials and wraps them in a cached provider.
    #[cfg(all(feature = "credentials-imds", feature = "blocking"))]
    pub fn from_imds_blocking() -> Result<Self> {
        Self::from_imds_blocking_with_tls_root_store(CredentialsTlsRootStore::BackendDefault)
    }

    /// Loads IMDS credentials and wraps them in a cached provider.
    #[cfg(all(feature = "credentials-imds", feature = "blocking"))]
    pub fn from_imds_blocking_with_tls_root_store(
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let initial = crate::credentials::imds::load_blocking(tls_root_store.into_reqx())?;
        let provider = CachedProvider::new(ImdsProvider { tls_root_store }).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    /// Assumes a role using static source credentials (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self> {
        Self::assume_role_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            source_credentials,
            CredentialsTlsRootStore::BackendDefault,
        )
        .await
    }

    /// Assumes a role using static source credentials and a specific trust root policy (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role_with_tls_root_store(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        Self::assume_role_with_provider_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            Arc::new(StaticCredentialsProvider::new(source_credentials)),
            tls_root_store,
        )
        .await
    }

    /// Assumes a role using static source credentials (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_blocking(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self> {
        Self::assume_role_blocking_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            source_credentials,
            CredentialsTlsRootStore::BackendDefault,
        )
    }

    /// Assumes a role using static source credentials and a specific trust root policy (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_blocking_with_tls_root_store(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        Self::assume_role_with_provider_blocking_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            Arc::new(StaticCredentialsProvider::new(source_credentials)),
            tls_root_store,
        )
    }

    /// Loads web identity credentials from env vars (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn from_web_identity_env() -> Result<Self> {
        Self::from_web_identity_env_with_tls_root_store(CredentialsTlsRootStore::BackendDefault)
            .await
    }

    /// Loads web identity credentials from env vars and a specific trust root policy (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn from_web_identity_env_with_tls_root_store(
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let provider = StsWebIdentityProvider { tls_root_store };
        let initial = provider.credentials_async().await?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    /// Loads web identity credentials from env vars (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn from_web_identity_env_blocking() -> Result<Self> {
        Self::from_web_identity_env_blocking_with_tls_root_store(
            CredentialsTlsRootStore::BackendDefault,
        )
    }

    /// Loads web identity credentials from env vars and a specific trust root policy (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn from_web_identity_env_blocking_with_tls_root_store(
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let provider = StsWebIdentityProvider { tls_root_store };
        let initial = provider.credentials_blocking()?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    /// Assumes a role using a credentials provider (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role_with_provider(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
    ) -> Result<Self> {
        Self::assume_role_with_provider_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            source,
            CredentialsTlsRootStore::BackendDefault,
        )
        .await
    }

    /// Assumes a role using a credentials provider and a specific trust root policy (async).
    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role_with_provider_with_tls_root_store(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let provider = StsAssumeRoleProvider {
            region,
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            source,
            tls_root_store,
        };
        let initial = provider.credentials_async().await?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    /// Assumes a role using a credentials provider (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_with_provider_blocking(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
    ) -> Result<Self> {
        Self::assume_role_with_provider_blocking_with_tls_root_store(
            region,
            role_arn,
            role_session_name,
            source,
            CredentialsTlsRootStore::BackendDefault,
        )
    }

    /// Assumes a role using a credentials provider and a specific trust root policy (blocking).
    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_with_provider_blocking_with_tls_root_store(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
        tls_root_store: CredentialsTlsRootStore,
    ) -> Result<Self> {
        let provider = StsAssumeRoleProvider {
            region,
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            source,
            tls_root_store,
        };
        let initial = provider.credentials_blocking()?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(feature = "async")]
    pub(crate) fn static_credentials(&self) -> Option<&Credentials> {
        match self {
            Self::Static(creds) => Some(creds),
            Self::Anonymous | Self::Provider(_) => None,
        }
    }

    #[cfg(feature = "async")]
    pub(crate) async fn credentials_snapshot_async(&self) -> Result<Option<CredentialsSnapshot>> {
        match self {
            Self::Anonymous => Ok(None),
            Self::Static(creds) => Ok(Some(CredentialsSnapshot::new(creds.clone()))),
            Self::Provider(provider) => provider.credentials_async().await.map(Some),
        }
    }

    #[cfg(feature = "blocking")]
    pub(crate) fn credentials_snapshot_blocking(&self) -> Result<Option<CredentialsSnapshot>> {
        match self {
            Self::Anonymous => Ok(None),
            Self::Static(creds) => Ok(Some(CredentialsSnapshot::new(creds.clone()))),
            Self::Provider(provider) => provider.credentials_blocking().map(Some),
        }
    }
}
