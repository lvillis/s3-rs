#[cfg(all(feature = "blocking", not(feature = "async")))]
use std::sync::{Condvar, Mutex};
#[cfg(any(feature = "async", feature = "blocking"))]
use std::time::Duration;

#[cfg(any(feature = "async", feature = "blocking"))]
use time::OffsetDateTime;

#[cfg(any(feature = "async", feature = "blocking"))]
use crate::{Error, Result};

#[cfg(feature = "async")]
use super::CredentialsFuture;
#[cfg(any(feature = "async", feature = "blocking"))]
use super::{CredentialsProvider, CredentialsSnapshot};

#[cfg(any(feature = "async", feature = "blocking"))]
#[derive(Debug)]
struct CachedState {
    cached: Option<CredentialsSnapshot>,
    refreshing: bool,
    last_refresh_attempt: Option<std::time::Instant>,
}

#[cfg(any(feature = "async", feature = "blocking"))]
enum RefreshDecision {
    UseCached(CredentialsSnapshot),
    Wait,
    Refresh {
        fallback: Option<CredentialsSnapshot>,
    },
}

#[cfg(feature = "async")]
type CachedStateLock = tokio::sync::Mutex<CachedState>;
#[cfg(all(not(feature = "async"), feature = "blocking"))]
type CachedStateLock = Mutex<CachedState>;

#[cfg(feature = "blocking")]
enum BlockingRefreshWait {
    #[cfg(all(feature = "blocking", not(feature = "async")))]
    Condvar,
    #[cfg(all(feature = "blocking", feature = "async"))]
    Epoch(u64),
}

/// Cached credentials wrapper with refresh and throttling.
///
/// This wrapper adds three behaviors to an underlying [`CredentialsProvider`]:
///
/// - caches the latest usable [`CredentialsSnapshot`]
/// - refreshes early before expiry
/// - coalesces concurrent refreshes so only one caller performs the refresh work
#[cfg(any(feature = "async", feature = "blocking"))]
#[derive(Debug)]
pub struct CachedProvider<P> {
    pub(super) inner: P,
    refresh_before: Duration,
    min_refresh_interval: Duration,
    state: CachedStateLock,
    #[cfg(all(feature = "blocking", not(feature = "async")))]
    condvar: Condvar,
    #[cfg(feature = "async")]
    notify: tokio::sync::Notify,
    #[cfg(all(feature = "blocking", feature = "async"))]
    refresh_epoch: std::sync::Mutex<u64>,
    #[cfg(all(feature = "blocking", feature = "async"))]
    refresh_condvar: std::sync::Condvar,
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl<P> CachedProvider<P>
where
    P: CredentialsProvider,
{
    /// Wraps a provider with caching and refresh behavior.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            refresh_before: Duration::from_secs(300),
            min_refresh_interval: Duration::from_secs(5),
            state: CachedStateLock::new(CachedState {
                cached: None,
                refreshing: false,
                last_refresh_attempt: None,
            }),
            #[cfg(all(feature = "blocking", not(feature = "async")))]
            condvar: Condvar::new(),
            #[cfg(feature = "async")]
            notify: tokio::sync::Notify::new(),
            #[cfg(all(feature = "blocking", feature = "async"))]
            refresh_epoch: std::sync::Mutex::new(0),
            #[cfg(all(feature = "blocking", feature = "async"))]
            refresh_condvar: std::sync::Condvar::new(),
        }
    }

    /// Sets how long before expiration to refresh.
    pub fn refresh_before(mut self, duration: Duration) -> Self {
        self.refresh_before = duration;
        self
    }

    /// Sets the minimum interval between refresh attempts.
    pub fn min_refresh_interval(mut self, duration: Duration) -> Self {
        self.min_refresh_interval = duration;
        self
    }

    /// Seeds the cache with an initial snapshot.
    pub fn with_initial(self, snapshot: CredentialsSnapshot) -> Self {
        self.set_initial_snapshot(snapshot);
        self
    }

    /// Forces a refresh in async mode.
    #[cfg(feature = "async")]
    pub async fn force_refresh_async(&self) -> Result<CredentialsSnapshot> {
        self.get_async(true).await
    }

    /// Forces a refresh in blocking mode.
    #[cfg(feature = "blocking")]
    pub fn force_refresh_blocking(&self) -> Result<CredentialsSnapshot> {
        self.get_blocking(true)
    }

    #[cfg(feature = "async")]
    fn set_initial_snapshot(&self, snapshot: CredentialsSnapshot) {
        let mut state = self
            .state
            .try_lock()
            .expect("cache state must be unlocked during initialization");
        state.cached = Some(snapshot);
    }

    #[cfg(all(feature = "blocking", not(feature = "async")))]
    fn set_initial_snapshot(&self, snapshot: CredentialsSnapshot) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.cached = Some(snapshot);
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
        match snapshot.expires_at() {
            Some(expires_at) => now + self.refresh_before >= expires_at,
            None => false,
        }
    }

    fn is_expired(snapshot: &CredentialsSnapshot, now: OffsetDateTime) -> bool {
        snapshot
            .expires_at()
            .is_some_and(|expires_at| now >= expires_at)
    }

    fn can_attempt_refresh(&self, state: &CachedState, now: std::time::Instant) -> bool {
        self.refresh_throttle_remaining(state, now).is_none()
    }

    fn refresh_throttle_remaining(
        &self,
        state: &CachedState,
        now: std::time::Instant,
    ) -> Option<Duration> {
        let last = state.last_refresh_attempt?;
        let elapsed = now.saturating_duration_since(last);
        if elapsed >= self.min_refresh_interval {
            None
        } else {
            Some(self.min_refresh_interval - elapsed)
        }
    }

    fn throttled_refresh_error(retry_after: Duration) -> Error {
        Error::transport(
            format!(
                "credentials refresh throttled; retry after {}ms",
                retry_after.as_millis()
            ),
            None,
        )
    }

    fn begin_refresh(
        &self,
        state: &mut CachedState,
        now_utc: OffsetDateTime,
        now: std::time::Instant,
        force: bool,
    ) -> Result<RefreshDecision> {
        if let Some(cached) = state.cached.as_ref() {
            if !self.should_refresh(cached, now_utc, force) {
                return Ok(RefreshDecision::UseCached(cached.clone()));
            }

            if !force && !Self::is_expired(cached, now_utc) && !self.can_attempt_refresh(state, now)
            {
                return Ok(RefreshDecision::UseCached(cached.clone()));
            }
        }

        if state.refreshing {
            return Ok(RefreshDecision::Wait);
        }

        let has_usable_fallback = state
            .cached
            .as_ref()
            .is_some_and(|cached| !Self::is_expired(cached, now_utc));
        if !force
            && !has_usable_fallback
            && let Some(retry_after) = self.refresh_throttle_remaining(state, now)
        {
            return Err(Self::throttled_refresh_error(retry_after));
        }

        state.refreshing = true;
        state.last_refresh_attempt = Some(now);
        Ok(RefreshDecision::Refresh {
            fallback: state.cached.clone(),
        })
    }

    fn finish_refresh_state(
        state: &mut CachedState,
        fallback: Option<CredentialsSnapshot>,
        refreshed: Result<CredentialsSnapshot>,
    ) -> Result<CredentialsSnapshot> {
        state.refreshing = false;

        match refreshed {
            Ok(snapshot) => {
                state.cached = Some(snapshot.clone());
                Ok(snapshot)
            }
            Err(err) => {
                let fallback_now = OffsetDateTime::now_utc();
                if let Some(snapshot) = fallback.filter(|s| !Self::is_expired(s, fallback_now)) {
                    return Ok(snapshot);
                }
                Err(err)
            }
        }
    }

    fn notify_refresh_waiters(&self) {
        #[cfg(feature = "async")]
        self.notify.notify_waiters();

        #[cfg(all(feature = "blocking", feature = "async"))]
        self.notify_blocking_refresh_waiters();

        #[cfg(all(feature = "blocking", not(feature = "async")))]
        self.condvar.notify_all();
    }

    #[cfg(all(feature = "blocking", not(feature = "async")))]
    fn with_blocking_state<R>(&self, f: impl FnOnce(&mut CachedState) -> R) -> R {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut state)
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn with_blocking_state<R>(&self, f: impl FnOnce(&mut CachedState) -> R) -> R {
        let mut state = self.state.blocking_lock();
        f(&mut state)
    }

    #[cfg(all(feature = "blocking", not(feature = "async")))]
    fn current_blocking_refresh_wait(&self) -> BlockingRefreshWait {
        BlockingRefreshWait::Condvar
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn current_blocking_refresh_wait(&self) -> BlockingRefreshWait {
        BlockingRefreshWait::Epoch(self.observed_refresh_epoch())
    }

    #[cfg(all(feature = "blocking", not(feature = "async")))]
    fn wait_for_blocking_refresh(&self, _wait: BlockingRefreshWait) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.refreshing {
            state = self
                .condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn wait_for_blocking_refresh(&self, wait: BlockingRefreshWait) {
        match wait {
            BlockingRefreshWait::Epoch(observed_epoch) => {
                self.wait_for_refresh_epoch_change(observed_epoch);
            }
        }
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn observed_refresh_epoch(&self) -> u64 {
        *self
            .refresh_epoch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn wait_for_refresh_epoch_change(&self, observed_epoch: u64) {
        let mut epoch = self
            .refresh_epoch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *epoch == observed_epoch {
            epoch = self
                .refresh_condvar
                .wait(epoch)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    #[cfg(all(feature = "blocking", feature = "async"))]
    fn notify_blocking_refresh_waiters(&self) {
        let mut epoch = self
            .refresh_epoch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *epoch = epoch.wrapping_add(1);
        self.refresh_condvar.notify_all();
    }

    #[cfg(feature = "blocking")]
    fn get_blocking(&self, force: bool) -> Result<CredentialsSnapshot> {
        use std::time::Instant;

        enum BlockingDecision {
            UseCached(CredentialsSnapshot),
            Wait(BlockingRefreshWait),
            Refresh {
                fallback: Option<CredentialsSnapshot>,
            },
        }

        loop {
            let now_utc = OffsetDateTime::now_utc();
            let decision = self.with_blocking_state(|state| {
                match self.begin_refresh(state, now_utc, Instant::now(), force) {
                    Ok(RefreshDecision::UseCached(snapshot)) => {
                        Ok(BlockingDecision::UseCached(snapshot))
                    }
                    Ok(RefreshDecision::Wait) => {
                        Ok(BlockingDecision::Wait(self.current_blocking_refresh_wait()))
                    }
                    Ok(RefreshDecision::Refresh { fallback }) => {
                        Ok(BlockingDecision::Refresh { fallback })
                    }
                    Err(err) => Err(err),
                }
            })?;

            match decision {
                BlockingDecision::UseCached(snapshot) => return Ok(snapshot),
                BlockingDecision::Wait(wait) => {
                    self.wait_for_blocking_refresh(wait);
                    continue;
                }
                BlockingDecision::Refresh { fallback } => {
                    let refreshed = self.inner.credentials_blocking();
                    let result = self.with_blocking_state(|state| {
                        Self::finish_refresh_state(state, fallback, refreshed)
                    });
                    self.notify_refresh_waiters();
                    return result;
                }
            }
        }
    }

    #[cfg(feature = "async")]
    async fn get_async(&self, force: bool) -> Result<CredentialsSnapshot> {
        use std::time::Instant;

        loop {
            let now_utc = OffsetDateTime::now_utc();
            let mut fallback = None;
            let notified = {
                let mut state = self.state.lock().await;

                match self.begin_refresh(&mut state, now_utc, Instant::now(), force)? {
                    RefreshDecision::UseCached(snapshot) => return Ok(snapshot),
                    RefreshDecision::Wait => Some(self.notify.notified()),
                    RefreshDecision::Refresh {
                        fallback: refresh_fallback,
                    } => {
                        fallback = refresh_fallback;
                        None
                    }
                }
            };

            if let Some(notified) = notified {
                notified.await;
                continue;
            }

            let refreshed = self.inner.credentials_async().await;

            let mut state = self.state.lock().await;
            let result = Self::finish_refresh_state(&mut state, fallback, refreshed);
            drop(state);
            self.notify_refresh_waiters();
            return result;
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
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
