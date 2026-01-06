use std::{
    fmt,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

#[cfg(feature = "async")]
use std::{future::Future, pin::Pin};

use time::OffsetDateTime;

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct CredentialsSnapshot {
    credentials: Credentials,
    expires_at: Option<OffsetDateTime>,
}

impl CredentialsSnapshot {
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            expires_at: None,
        }
    }

    pub fn with_expires_at(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
}

#[cfg(feature = "async")]
pub type CredentialsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CredentialsSnapshot>> + Send + 'a>>;

pub trait CredentialsProvider: fmt::Debug + Send + Sync {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_>;

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot>;
}

pub type DynCredentialsProvider = Arc<dyn CredentialsProvider>;

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
struct ImdsProvider;

#[cfg(feature = "credentials-imds")]
impl CredentialsProvider for ImdsProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(async move { crate::credentials::imds::load_async().await })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        crate::credentials::imds::load_blocking()
    }
}

#[cfg(feature = "credentials-sts")]
#[derive(Debug)]
struct StsAssumeRoleProvider {
    region: Region,
    role_arn: String,
    role_session_name: String,
    source: DynCredentialsProvider,
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
        )
    }
}

#[cfg(feature = "credentials-sts")]
#[derive(Debug, Clone, Copy)]
struct StsWebIdentityProvider;

#[cfg(feature = "credentials-sts")]
impl CredentialsProvider for StsWebIdentityProvider {
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(
            async move { crate::credentials::sts::assume_role_with_web_identity_env_async().await },
        )
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        crate::credentials::sts::assume_role_with_web_identity_env_blocking()
    }
}

#[derive(Debug)]
struct CachedState {
    cached: Option<CredentialsSnapshot>,
    refreshing: bool,
    last_refresh_attempt: Option<std::time::Instant>,
}

#[derive(Debug)]
pub struct CachedProvider<P> {
    inner: P,
    refresh_before: Duration,
    min_refresh_interval: Duration,
    state: Mutex<CachedState>,
    condvar: Condvar,
    #[cfg(feature = "async")]
    notify: tokio::sync::Notify,
}

impl<P> CachedProvider<P>
where
    P: CredentialsProvider,
{
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            refresh_before: Duration::from_secs(300),
            min_refresh_interval: Duration::from_secs(5),
            state: Mutex::new(CachedState {
                cached: None,
                refreshing: false,
                last_refresh_attempt: None,
            }),
            condvar: Condvar::new(),
            #[cfg(feature = "async")]
            notify: tokio::sync::Notify::new(),
        }
    }

    pub fn refresh_before(mut self, duration: Duration) -> Self {
        self.refresh_before = duration;
        self
    }

    pub fn min_refresh_interval(mut self, duration: Duration) -> Self {
        self.min_refresh_interval = duration;
        self
    }

    pub fn with_initial(self, snapshot: CredentialsSnapshot) -> Self {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.cached = Some(snapshot);
        drop(state);
        self
    }

    #[cfg(feature = "async")]
    pub async fn force_refresh_async(&self) -> Result<CredentialsSnapshot> {
        self.get_async(true).await
    }

    #[cfg(feature = "blocking")]
    pub fn force_refresh_blocking(&self) -> Result<CredentialsSnapshot> {
        self.get_blocking(true)
    }

    fn should_refresh(
        &self,
        snapshot: &CredentialsSnapshot,
        now: OffsetDateTime,
        force: bool,
    ) -> bool {
        if force {
            return true;
        }
        match snapshot.expires_at {
            Some(expires_at) => now + self.refresh_before >= expires_at,
            None => false,
        }
    }

    fn is_expired(snapshot: &CredentialsSnapshot, now: OffsetDateTime) -> bool {
        snapshot
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    fn can_attempt_refresh(&self, state: &CachedState, now: std::time::Instant) -> bool {
        match state.last_refresh_attempt {
            Some(last) => now.duration_since(last) >= self.min_refresh_interval,
            None => true,
        }
    }

    #[cfg(feature = "blocking")]
    fn get_blocking(&self, force: bool) -> Result<CredentialsSnapshot> {
        use std::time::Instant;

        loop {
            let now_utc = OffsetDateTime::now_utc();
            let (fallback, should_refresh, wait) = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

                if let Some(cached) = state.cached.as_ref() {
                    if !self.should_refresh(cached, now_utc, force) {
                        return Ok(cached.clone());
                    }

                    if !force
                        && !Self::is_expired(cached, now_utc)
                        && !self.can_attempt_refresh(&state, Instant::now())
                    {
                        return Ok(cached.clone());
                    }
                } else if !self.can_attempt_refresh(&state, Instant::now()) {
                    // No cached credentials and we're throttled; keep waiting.
                }

                if state.refreshing {
                    (state.cached.clone(), false, true)
                } else {
                    state.refreshing = true;
                    state.last_refresh_attempt = Some(Instant::now());
                    (state.cached.clone(), true, false)
                }
            };

            if wait {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                while state.refreshing {
                    state = self.condvar.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                continue;
            }

            if !should_refresh {
                continue;
            }

            let refreshed = self.inner.credentials_blocking();

            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.refreshing = false;
            match refreshed {
                Ok(snapshot) => {
                    state.cached = Some(snapshot.clone());
                    drop(state);
                    self.condvar.notify_all();
                    #[cfg(feature = "async")]
                    self.notify.notify_waiters();
                    return Ok(snapshot);
                }
                Err(err) => {
                    let fallback = fallback.filter(|s| !Self::is_expired(s, now_utc));
                    drop(state);
                    self.condvar.notify_all();
                    #[cfg(feature = "async")]
                    self.notify.notify_waiters();
                    if let Some(snapshot) = fallback {
                        return Ok(snapshot);
                    }
                    return Err(err);
                }
            }
        }
    }

    #[cfg(feature = "async")]
    async fn get_async(&self, force: bool) -> Result<CredentialsSnapshot> {
        use std::time::Instant;

        loop {
            let now_utc = OffsetDateTime::now_utc();
            let (fallback, notified) = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

                if let Some(cached) = state.cached.as_ref() {
                    if !self.should_refresh(cached, now_utc, force) {
                        return Ok(cached.clone());
                    }

                    if !force
                        && !Self::is_expired(cached, now_utc)
                        && !self.can_attempt_refresh(&state, Instant::now())
                    {
                        return Ok(cached.clone());
                    }
                }

                if state.refreshing {
                    let notified = self.notify.notified();
                    (state.cached.clone(), Some(notified))
                } else {
                    state.refreshing = true;
                    state.last_refresh_attempt = Some(Instant::now());
                    (state.cached.clone(), None)
                }
            };

            if let Some(notified) = notified {
                notified.await;
                continue;
            }

            let refreshed = self.inner.credentials_async().await;

            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.refreshing = false;
            match refreshed {
                Ok(snapshot) => {
                    state.cached = Some(snapshot.clone());
                    drop(state);
                    self.condvar.notify_all();
                    self.notify.notify_waiters();
                    return Ok(snapshot);
                }
                Err(err) => {
                    let fallback = fallback.filter(|s| !Self::is_expired(s, now_utc));
                    drop(state);
                    self.condvar.notify_all();
                    self.notify.notify_waiters();
                    if let Some(snapshot) = fallback {
                        return Ok(snapshot);
                    }
                    return Err(err);
                }
            }
        }
    }
}

impl<P> CredentialsProvider for CachedProvider<P>
where
    P: CredentialsProvider,
{
    #[cfg(feature = "async")]
    fn credentials_async(&self) -> CredentialsFuture<'_> {
        Box::pin(async move { self.get_async(false).await })
    }

    #[cfg(feature = "blocking")]
    fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
        self.get_blocking(false)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Region(String);

impl Region {
    pub fn new(value: impl Into<String>) -> Result<Self> {
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

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
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

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Auth {
    Anonymous,
    Static(Credentials),
    Provider(DynCredentialsProvider),
}

impl Auth {
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

    pub fn provider(provider: DynCredentialsProvider) -> Self {
        Self::Provider(provider)
    }

    #[cfg(feature = "credentials-profile")]
    pub fn from_profile(profile: impl AsRef<str>) -> Result<Self> {
        let creds = crate::credentials::profile::load_profile_credentials(profile.as_ref())?;
        Ok(Self::Static(creds))
    }

    #[cfg(feature = "credentials-profile")]
    pub fn from_profile_env() -> Result<Self> {
        Self::from_profile(crate::credentials::profile::profile_from_env())
    }

    #[cfg(all(feature = "credentials-imds", feature = "async"))]
    pub async fn from_imds() -> Result<Self> {
        let initial = crate::credentials::imds::load_async().await?;
        let provider = CachedProvider::new(ImdsProvider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(all(feature = "credentials-imds", feature = "blocking"))]
    pub fn from_imds_blocking() -> Result<Self> {
        let initial = crate::credentials::imds::load_blocking()?;
        let provider = CachedProvider::new(ImdsProvider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self> {
        Self::assume_role_with_provider(
            region,
            role_arn,
            role_session_name,
            Arc::new(StaticCredentialsProvider::new(source_credentials)),
        )
        .await
    }

    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_blocking(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source_credentials: Credentials,
    ) -> Result<Self> {
        Self::assume_role_with_provider_blocking(
            region,
            role_arn,
            role_session_name,
            Arc::new(StaticCredentialsProvider::new(source_credentials)),
        )
    }

    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn from_web_identity_env() -> Result<Self> {
        let provider = StsWebIdentityProvider;
        let initial = provider.credentials_async().await?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn from_web_identity_env_blocking() -> Result<Self> {
        let provider = StsWebIdentityProvider;
        let initial = provider.credentials_blocking()?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(all(feature = "credentials-sts", feature = "async"))]
    pub async fn assume_role_with_provider(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
    ) -> Result<Self> {
        let provider = StsAssumeRoleProvider {
            region,
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            source,
        };
        let initial = provider.credentials_async().await?;
        let provider = CachedProvider::new(provider).with_initial(initial);
        Ok(Self::Provider(Arc::new(provider)))
    }

    #[cfg(all(feature = "credentials-sts", feature = "blocking"))]
    pub fn assume_role_with_provider_blocking(
        region: Region,
        role_arn: impl Into<String>,
        role_session_name: impl Into<String>,
        source: DynCredentialsProvider,
    ) -> Result<Self> {
        let provider = StsAssumeRoleProvider {
            region,
            role_arn: role_arn.into(),
            role_session_name: role_session_name.into(),
            source,
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

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressingStyle {
    Auto,
    Path,
    VirtualHosted,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "blocking")]
    use std::sync::Condvar;
    use std::sync::Mutex;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn region_validates_non_empty() {
        assert!(Region::new("").is_err());
        assert!(Region::new("   ").is_err());
        assert!(Region::new("us-east-1").is_ok());
    }

    #[test]
    fn credentials_validate_and_redact_in_debug() {
        assert!(Credentials::new("", "secret").is_err());
        assert!(Credentials::new("akid", "").is_err());

        let creds = Credentials::new("AKIA1234567890", "SECRET1234567890")
            .unwrap()
            .with_session_token("TOKEN1234567890")
            .unwrap();

        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("SECRET1234567890"));
        assert!(!dbg.contains("TOKEN1234567890"));
        assert!(dbg.contains("<redacted>"));
    }

    #[derive(Debug)]
    struct CountingFailProvider {
        calls: Arc<AtomicUsize>,
    }

    impl CredentialsProvider for CountingFailProvider {
        #[cfg(feature = "async")]
        fn credentials_async(&self) -> CredentialsFuture<'_> {
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(Error::invalid_config("refresh failed"))
            })
        }

        #[cfg(feature = "blocking")]
        fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::invalid_config("refresh failed"))
        }
    }

    #[derive(Debug)]
    struct CountingOkProvider {
        calls: Arc<AtomicUsize>,
        expires_in: time::Duration,
    }

    impl CountingOkProvider {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self {
                calls,
                expires_in: time::Duration::seconds(3600),
            }
        }
    }

    impl CredentialsProvider for CountingOkProvider {
        #[cfg(feature = "async")]
        fn credentials_async(&self) -> CredentialsFuture<'_> {
            let calls = self.calls.clone();
            let expires_in = self.expires_in;
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let creds = Credentials::new(format!("AKIA_{n}"), "SECRET_TEST").unwrap();
                Ok(CredentialsSnapshot::new(creds)
                    .with_expires_at(OffsetDateTime::now_utc() + expires_in))
            })
        }

        #[cfg(feature = "blocking")]
        fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let creds = Credentials::new(format!("AKIA_{n}"), "SECRET_TEST").unwrap();
            Ok(CredentialsSnapshot::new(creds)
                .with_expires_at(OffsetDateTime::now_utc() + self.expires_in))
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn cached_provider_returns_stale_on_refresh_error_async() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingFailProvider {
            calls: calls.clone(),
        };

        let initial =
            CredentialsSnapshot::new(Credentials::new("AKIA_TEST", "SECRET_TEST").unwrap())
                .with_expires_at(OffsetDateTime::now_utc() + time::Duration::seconds(60));

        let cached = CachedProvider::new(inner)
            .min_refresh_interval(Duration::from_secs(0))
            .with_initial(initial.clone());

        let snapshot = cached.credentials_async().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            snapshot.credentials().access_key_id,
            initial.credentials().access_key_id
        );
        assert_eq!(snapshot.expires_at(), initial.expires_at());
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn cached_provider_singleflight_refresh_async() {
        use tokio::sync::oneshot;

        #[derive(Debug)]
        struct SlowProvider {
            calls: Arc<AtomicUsize>,
            started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
            proceed: Arc<tokio::sync::Notify>,
        }

        impl CredentialsProvider for SlowProvider {
            fn credentials_async(&self) -> CredentialsFuture<'_> {
                let calls = self.calls.clone();
                let started = self.started.clone();
                let proceed = self.proceed.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if let Some(tx) = started.lock().unwrap_or_else(|p| p.into_inner()).take() {
                        let _ = tx.send(());
                    }
                    proceed.notified().await;
                    let creds = Credentials::new("AKIA_TEST", "SECRET_TEST").unwrap();
                    Ok(CredentialsSnapshot::new(creds)
                        .with_expires_at(OffsetDateTime::now_utc() + time::Duration::seconds(60)))
                })
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = oneshot::channel();
        let inner = SlowProvider {
            calls: calls.clone(),
            started: Arc::new(Mutex::new(Some(tx))),
            proceed: Arc::new(tokio::sync::Notify::new()),
        };

        let cached = Arc::new(
            CachedProvider::new(inner)
                .refresh_before(Duration::from_secs(0))
                .min_refresh_interval(Duration::from_secs(0)),
        );
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let cached = cached.clone();
            tasks.push(tokio::spawn(async move {
                cached
                    .credentials_async()
                    .await
                    .map(|s| s.credentials().access_key_id.clone())
            }));
        }

        let _ = rx.await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cached.inner.proceed.notify_one();

        for task in tasks {
            let key = task.await.unwrap().unwrap();
            assert_eq!(key, "AKIA_TEST");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn cached_provider_refresh_before_and_throttle_async() {
        let now = OffsetDateTime::now_utc();

        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingOkProvider::new(calls.clone());

        let initial = CredentialsSnapshot::new(Credentials::new("OLD", "SECRET_TEST").unwrap())
            .with_expires_at(now + time::Duration::seconds(60));
        let cached = CachedProvider::new(inner)
            .refresh_before(Duration::from_secs(10))
            .with_initial(initial);

        let snapshot = cached.credentials_async().await.unwrap();
        assert_eq!(snapshot.credentials().access_key_id, "OLD");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingFailProvider {
            calls: calls.clone(),
        };
        let initial = CredentialsSnapshot::new(Credentials::new("STALE", "SECRET_TEST").unwrap())
            .with_expires_at(now + time::Duration::seconds(60));
        let cached = CachedProvider::new(inner)
            .min_refresh_interval(Duration::from_secs(60))
            .with_initial(initial.clone());

        let first = cached.credentials_async().await.unwrap();
        let second = cached.credentials_async().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.credentials().access_key_id, "STALE");
        assert_eq!(second.credentials().access_key_id, "STALE");
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn cached_provider_force_refresh_bypasses_throttle_async() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingOkProvider::new(calls.clone());
        let cached = CachedProvider::new(inner).min_refresh_interval(Duration::from_secs(60));

        let first = cached.force_refresh_async().await.unwrap();
        let second = cached.force_refresh_async().await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_ne!(
            first.credentials().access_key_id,
            second.credentials().access_key_id
        );
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn cached_provider_returns_stale_on_refresh_error_blocking() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingFailProvider {
            calls: calls.clone(),
        };

        let initial =
            CredentialsSnapshot::new(Credentials::new("AKIA_TEST", "SECRET_TEST").unwrap())
                .with_expires_at(OffsetDateTime::now_utc() + time::Duration::seconds(60));

        let cached = CachedProvider::new(inner)
            .min_refresh_interval(Duration::from_secs(0))
            .with_initial(initial.clone());

        let snapshot = cached.credentials_blocking().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            snapshot.credentials().access_key_id,
            initial.credentials().access_key_id
        );
        assert_eq!(snapshot.expires_at(), initial.expires_at());
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn cached_provider_singleflight_refresh_blocking() {
        use std::{sync::mpsc, thread};

        #[derive(Debug)]
        struct SlowProvider {
            calls: Arc<AtomicUsize>,
            started: Arc<Mutex<Option<mpsc::Sender<()>>>>,
            state: Arc<(Mutex<bool>, Condvar)>,
        }

        impl CredentialsProvider for SlowProvider {
            fn credentials_blocking(&self) -> Result<CredentialsSnapshot> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(tx) = self
                    .started
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                {
                    let _ = tx.send(());
                }
                let (lock, cvar) = &*self.state;
                let mut ready = lock.lock().unwrap_or_else(|p| p.into_inner());
                while !*ready {
                    ready = cvar.wait(ready).unwrap_or_else(|p| p.into_inner());
                }
                drop(ready);
                let creds = Credentials::new("AKIA_TEST", "SECRET_TEST").unwrap();
                Ok(CredentialsSnapshot::new(creds)
                    .with_expires_at(OffsetDateTime::now_utc() + time::Duration::seconds(60)))
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let inner = SlowProvider {
            calls: calls.clone(),
            started: Arc::new(Mutex::new(Some(tx))),
            state: state.clone(),
        };

        let cached = Arc::new(
            CachedProvider::new(inner)
                .refresh_before(Duration::from_secs(0))
                .min_refresh_interval(Duration::from_secs(0)),
        );
        let mut threads = Vec::new();
        for _ in 0..10 {
            let cached = cached.clone();
            threads.push(thread::spawn(move || {
                cached
                    .credentials_blocking()
                    .map(|s| s.credentials().access_key_id.clone())
            }));
        }

        let _ = rx.recv();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        {
            let (lock, cvar) = &*state;
            let mut ready = lock.lock().unwrap_or_else(|p| p.into_inner());
            *ready = true;
            cvar.notify_all();
        }

        for t in threads {
            let key = t.join().unwrap().unwrap();
            assert_eq!(key, "AKIA_TEST");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn cached_provider_refresh_before_and_throttle_blocking() {
        let now = OffsetDateTime::now_utc();

        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingOkProvider::new(calls.clone());

        let initial = CredentialsSnapshot::new(Credentials::new("OLD", "SECRET_TEST").unwrap())
            .with_expires_at(now + time::Duration::seconds(60));
        let cached = CachedProvider::new(inner)
            .refresh_before(Duration::from_secs(10))
            .with_initial(initial);

        let snapshot = cached.credentials_blocking().unwrap();
        assert_eq!(snapshot.credentials().access_key_id, "OLD");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingFailProvider {
            calls: calls.clone(),
        };
        let initial = CredentialsSnapshot::new(Credentials::new("STALE", "SECRET_TEST").unwrap())
            .with_expires_at(now + time::Duration::seconds(60));
        let cached = CachedProvider::new(inner)
            .min_refresh_interval(Duration::from_secs(60))
            .with_initial(initial.clone());

        let first = cached.credentials_blocking().unwrap();
        let second = cached.credentials_blocking().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.credentials().access_key_id, "STALE");
        assert_eq!(second.credentials().access_key_id, "STALE");
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn cached_provider_force_refresh_bypasses_throttle_blocking() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingOkProvider::new(calls.clone());
        let cached = CachedProvider::new(inner).min_refresh_interval(Duration::from_secs(60));

        let first = cached.force_refresh_blocking().unwrap();
        let second = cached.force_refresh_blocking().unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_ne!(
            first.credentials().access_key_id,
            second.credentials().access_key_id
        );
    }
}
