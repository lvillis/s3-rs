use std::{sync::Arc, time::Duration};

use http::{HeaderMap, Method};
use time::OffsetDateTime;
use url::Url;

use crate::{
    api,
    auth::{AddressingStyle, Auth, Region},
    error::{Error, Result},
    transport::blocking_transport::{BlockingBody, BlockingTransport},
    util,
};

#[derive(Clone)]
pub struct BlockingClient {
    inner: Arc<Inner>,
}

pub struct BlockingClientBuilder {
    endpoint: Url,
    region: Option<String>,
    auth: Auth,
    addressing: AddressingStyle,
    retry: crate::transport::RetryConfig,
    timeout: Option<Duration>,
    user_agent: Option<String>,
}

struct Inner {
    endpoint: Url,
    region: Region,
    auth: Auth,
    addressing: AddressingStyle,
    transport: BlockingTransport,
}

impl BlockingClient {
    pub fn builder(endpoint: impl AsRef<str>) -> Result<BlockingClientBuilder> {
        BlockingClientBuilder::new(endpoint.as_ref())
    }

    pub fn objects(&self) -> api::BlockingObjectsService {
        api::BlockingObjectsService::new(self.clone())
    }

    pub fn buckets(&self) -> api::BlockingBucketsService {
        api::BlockingBucketsService::new(self.clone())
    }

    pub(crate) fn execute(
        &self,
        method: Method,
        bucket: Option<&str>,
        key: Option<&str>,
        query_params: Vec<(String, String)>,
        mut headers: HeaderMap,
        body: BlockingBody,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        #[cfg(feature = "tracing")]
        let _guard = tracing::info_span!(
            "s3.request",
            method = %method,
            bucket = bucket.unwrap_or(""),
            key = key.unwrap_or(""),
            host = self.inner.endpoint.host_str().unwrap_or(""),
        )
        .entered();

        let resolved = util::url::resolve_url(
            &self.inner.endpoint,
            bucket,
            key,
            &query_params,
            self.inner.addressing,
        )?;

        if let Some(creds) = self.inner.auth.credentials() {
            let now = OffsetDateTime::now_utc();
            let payload_hash = match &body {
                BlockingBody::Empty => util::signing::payload_hash_empty(),
                BlockingBody::Bytes(b) => util::signing::payload_hash_bytes(b),
            };

            util::signing::sign_headers(
                &method,
                &resolved,
                &mut headers,
                &payload_hash,
                &self.inner.region,
                creds,
                now,
            )?;
        }

        self.inner
            .transport
            .send(method, resolved.url, headers, body)
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
        let creds = self
            .inner
            .auth
            .credentials()
            .ok_or_else(|| Error::invalid_config("presign requires credentials"))?;

        let resolved = util::url::resolve_url(
            &self.inner.endpoint,
            Some(bucket),
            Some(key),
            &query_params,
            self.inner.addressing,
        )?;

        let now = OffsetDateTime::now_utc();
        util::signing::presign(
            method,
            resolved,
            util::signing::SigV4Params::for_s3(&self.inner.region, creds, now),
            expires_in,
            &query_params,
            &headers,
        )
    }
}

impl BlockingClientBuilder {
    fn new(endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint)
            .map_err(|_| Error::invalid_config("endpoint must be a valid absolute URL"))?;

        if endpoint.scheme() != "http" && endpoint.scheme() != "https" {
            return Err(Error::invalid_config(
                "endpoint scheme must be http or https",
            ));
        }
        if endpoint.host_str().is_none() {
            return Err(Error::invalid_config("endpoint must include host"));
        }
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(Error::invalid_config(
                "endpoint must not include query or fragment",
            ));
        }
        if endpoint.path() != "/" && !endpoint.path().is_empty() {
            return Err(Error::invalid_config("endpoint must not include a path"));
        }

        Ok(Self {
            endpoint,
            region: None,
            auth: Auth::Anonymous,
            addressing: AddressingStyle::Auto,
            retry: crate::transport::RetryConfig::default(),
            timeout: None,
            user_agent: None,
        })
    }

    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    pub fn addressing_style(mut self, style: AddressingStyle) -> Self {
        self.addressing = style;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_attempts(mut self, max_attempts: u32) -> Self {
        self.retry.max_attempts = max_attempts.max(1);
        self
    }

    pub fn base_retry_delay(mut self, delay: Duration) -> Self {
        self.retry.base_delay = delay;
        self
    }

    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.retry.max_delay = delay;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn build(self) -> Result<BlockingClient> {
        let region = self
            .region
            .ok_or_else(|| Error::invalid_config("region is required"))
            .and_then(Region::new)?;
        let transport = BlockingTransport::new(self.retry, self.user_agent, self.timeout)?;

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
