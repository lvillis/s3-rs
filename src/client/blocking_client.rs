use std::{sync::Arc, time::Duration};

use http::{HeaderMap, Method};
use reqx::advanced::TlsRootStore;
use time::OffsetDateTime;
use url::Url;

use super::common::{parse_endpoint, sign_with_snapshot, validate_presign_credentials_lifetime};

use crate::{
    api,
    auth::{AddressingStyle, Auth, Region},
    error::{Error, Result},
    transport::blocking_transport::{BlockingBody, BlockingResponse, BlockingTransport},
    util,
};

/// Trust root selection for blocking HTTPS requests.
///
/// This only affects the blocking transport when using HTTPS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BlockingTlsRootStore {
    /// Use the backend default trust roots.
    ///
    /// For `rustls`, this is WebPKI roots when enabled by feature flags.
    /// For `native-tls`, this follows the backend default behavior.
    #[default]
    BackendDefault,
    /// Force WebPKI roots.
    WebPki,
    /// Use platform/system trust verification.
    System,
}

/// Blocking S3 client.
#[derive(Clone)]
pub struct BlockingClient {
    inner: Arc<Inner>,
}

/// Builder for [`BlockingClient`].
pub struct BlockingClientBuilder {
    endpoint: Url,
    region: Option<String>,
    auth: Auth,
    addressing: AddressingStyle,
    retry: crate::transport::RetryConfig,
    timeout: Option<Duration>,
    user_agent: Option<String>,
    tls_root_store: BlockingTlsRootStore,
}

struct Inner {
    endpoint: Url,
    region: Region,
    auth: Auth,
    addressing: AddressingStyle,
    transport: BlockingTransport,
}

impl BlockingClient {
    /// Creates a client builder from an endpoint URL.
    pub fn builder(endpoint: impl AsRef<str>) -> Result<BlockingClientBuilder> {
        BlockingClientBuilder::new(endpoint.as_ref())
    }

    /// Returns the objects service.
    pub fn objects(&self) -> api::BlockingObjectsService {
        api::BlockingObjectsService::new(self.clone())
    }

    /// Returns the buckets service.
    pub fn buckets(&self) -> api::BlockingBucketsService {
        api::BlockingBucketsService::new(self.clone())
    }

    pub(crate) fn region(&self) -> &str {
        self.inner.region.as_str()
    }

    pub(crate) fn execute(
        &self,
        method: Method,
        bucket: Option<&str>,
        key: Option<&str>,
        query_params: Vec<(String, String)>,
        mut headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<BlockingResponse> {
        #[cfg(feature = "tracing")]
        let _guard = tracing::info_span!(
            "s3.request",
            method = %method,
            bucket_present = bucket.is_some(),
            key_present = key.is_some(),
            host = crate::transport::redacted_host_for_trace(&self.inner.endpoint),
        )
        .entered();

        let resolved = util::url::resolve_url(
            &self.inner.endpoint,
            bucket,
            key,
            &query_params,
            self.inner.addressing,
        )?;

        if let Some(snapshot) = self.inner.auth.credentials_snapshot_blocking()? {
            let now = OffsetDateTime::now_utc();
            let payload_hash = match &body {
                BlockingBody::Empty => util::signing::payload_hash_empty(),
                BlockingBody::Bytes(b) => util::signing::payload_hash_bytes(b),
                BlockingBody::Reader { .. } => util::signing::UNSIGNED_PAYLOAD.to_string(),
            };

            sign_with_snapshot(
                &method,
                &resolved,
                &mut headers,
                &payload_hash,
                &self.inner.region,
                &snapshot,
                now,
            )?;
        }

        self.inner
            .transport
            .send(method, resolved.url, headers, body)
    }

    pub(crate) fn execute_stream(
        &self,
        method: Method,
        bucket: Option<&str>,
        key: Option<&str>,
        query_params: Vec<(String, String)>,
        mut headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<reqx::blocking::ResponseStream> {
        let resolved = util::url::resolve_url(
            &self.inner.endpoint,
            bucket,
            key,
            &query_params,
            self.inner.addressing,
        )?;

        if let Some(snapshot) = self.inner.auth.credentials_snapshot_blocking()? {
            let now = OffsetDateTime::now_utc();
            let payload_hash = match &body {
                BlockingBody::Empty => util::signing::payload_hash_empty(),
                BlockingBody::Bytes(b) => util::signing::payload_hash_bytes(b),
                BlockingBody::Reader { .. } => util::signing::UNSIGNED_PAYLOAD.to_string(),
            };

            sign_with_snapshot(
                &method,
                &resolved,
                &mut headers,
                &payload_hash,
                &self.inner.region,
                &snapshot,
                now,
            )?;
        }

        self.inner
            .transport
            .send_stream(method, resolved.url, headers, body)
    }

    pub(crate) fn presign(
        &self,
        method: Method,
        bucket: &str,
        key: &str,
        expires_in: Duration,
        query_params: Vec<(String, String)>,
        headers: HeaderMap,
    ) -> Result<crate::types::PresignedRequest> {
        let snapshot = self
            .inner
            .auth
            .credentials_snapshot_blocking()?
            .ok_or_else(|| Error::invalid_config("presign requires credentials"))?;

        let resolved = util::url::resolve_url(
            &self.inner.endpoint,
            Some(bucket),
            Some(key),
            &query_params,
            self.inner.addressing,
        )?;

        let now = OffsetDateTime::now_utc();
        validate_presign_credentials_lifetime(&snapshot, expires_in, now)?;
        util::signing::presign(
            method,
            resolved,
            util::signing::SigV4Params::for_s3(&self.inner.region, snapshot.credentials(), now),
            expires_in,
            &query_params,
            &headers,
        )
    }
}

impl BlockingClientBuilder {
    fn new(endpoint: &str) -> Result<Self> {
        let endpoint = parse_endpoint(endpoint)?;

        Ok(Self {
            endpoint,
            region: None,
            auth: Auth::Anonymous,
            addressing: AddressingStyle::Auto,
            retry: crate::transport::RetryConfig::default(),
            timeout: None,
            user_agent: None,
            tls_root_store: BlockingTlsRootStore::BackendDefault,
        })
    }

    /// Sets the region used for signing.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Sets the authentication strategy.
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// Sets the bucket addressing style.
    pub fn addressing_style(mut self, style: AddressingStyle) -> Self {
        self.addressing = style;
        self
    }

    /// Sets a per-request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of retry attempts.
    pub fn max_attempts(mut self, max_attempts: u32) -> Self {
        self.retry.max_attempts = max_attempts.max(1);
        self
    }

    /// Sets the base delay for retries.
    pub fn base_retry_delay(mut self, delay: Duration) -> Self {
        self.retry.base_delay = delay;
        self
    }

    /// Sets the maximum delay for retries.
    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.retry.max_delay = delay;
        self
    }

    /// Sets the maximum delay honored from `Retry-After` hints.
    pub fn max_retry_after(mut self, delay: Duration) -> Self {
        self.retry.max_retry_after = delay;
        self
    }

    /// Overrides the default user agent.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Sets the trust root policy for blocking HTTPS requests.
    ///
    /// Builder default is `BackendDefault`.
    /// Use `System` for enterprise/private PKI environments that rely on OS trust stores.
    pub fn tls_root_store(mut self, tls_root_store: BlockingTlsRootStore) -> Self {
        self.tls_root_store = tls_root_store;
        self
    }

    /// Builds the client after validating configuration.
    pub fn build(self) -> Result<BlockingClient> {
        let region = self
            .region
            .ok_or_else(|| Error::invalid_config("region is required"))
            .and_then(Region::new)?;
        let transport = BlockingTransport::new(
            self.retry,
            self.user_agent,
            self.timeout,
            self.tls_root_store.into_reqx(),
        )?;

        Ok(BlockingClient {
            inner: Arc::new(Inner {
                endpoint: self.endpoint,
                region,
                auth: self.auth,
                addressing: self.addressing,
                transport,
            }),
        })
    }
}

impl BlockingTlsRootStore {
    pub(crate) const fn into_reqx(self) -> TlsRootStore {
        match self {
            Self::BackendDefault => TlsRootStore::BackendDefault,
            Self::WebPki => TlsRootStore::WebPki,
            Self::System => TlsRootStore::System,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_tls_root_store_to_backend_default() {
        let builder =
            BlockingClientBuilder::new("https://s3.example.com").expect("builder should parse");
        assert_eq!(builder.tls_root_store, BlockingTlsRootStore::BackendDefault);
    }

    #[test]
    fn builder_tls_root_store_override_is_applied() {
        let builder = BlockingClientBuilder::new("https://s3.example.com")
            .expect("builder should parse")
            .tls_root_store(BlockingTlsRootStore::System);
        assert_eq!(builder.tls_root_store, BlockingTlsRootStore::System);
    }

    #[test]
    fn builder_rejects_endpoint_with_user_info() {
        let err = match BlockingClientBuilder::new("https://user:pass@s3.example.com") {
            Ok(_) => panic!("endpoint with user info must be rejected"),
            Err(err) => err,
        };
        match err {
            Error::InvalidConfig { message } => {
                assert!(message.contains("must not include user info"));
            }
            other => panic!("expected invalid config, got {other:?}"),
        }
    }

    #[cfg(feature = "rustls")]
    #[test]
    fn build_accepts_webpki_on_rustls() {
        let client = BlockingClient::builder("https://s3.example.com")
            .expect("builder should parse")
            .region("us-east-1")
            .auth(Auth::Anonymous)
            .tls_root_store(BlockingTlsRootStore::WebPki)
            .build();
        assert!(client.is_ok(), "rustls should accept WebPki root store");
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    #[test]
    fn build_accepts_webpki_on_native_tls() {
        // reqx blocking transport (ureq backend) accepts WebPki roots on native-tls.
        let client = BlockingClient::builder("https://s3.example.com")
            .expect("builder should parse")
            .region("us-east-1")
            .auth(Auth::Anonymous)
            .tls_root_store(BlockingTlsRootStore::WebPki)
            .build();
        assert!(
            client.is_ok(),
            "native-tls should build with WebPki root store"
        );
    }
}
