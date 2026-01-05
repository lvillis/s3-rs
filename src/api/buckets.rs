use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use crate::{
    client::Client,
    error::{Error, Result},
    transport::async_transport::{AsyncBody, response_error},
    types::{
        BucketCorsConfiguration, BucketEncryptionConfiguration, BucketLifecycleConfiguration,
        BucketPublicAccessBlockConfiguration, BucketTagging, BucketVersioningConfiguration,
        CreateBucketOutput, DeleteBucketCorsOutput, DeleteBucketEncryptionOutput,
        DeleteBucketLifecycleOutput, DeleteBucketOutput, DeleteBucketPublicAccessBlockOutput,
        DeleteBucketTaggingOutput, HeadBucketOutput, ListBucketsOutput, PutBucketCorsOutput,
        PutBucketEncryptionOutput, PutBucketLifecycleOutput, PutBucketPublicAccessBlockOutput,
        PutBucketTaggingOutput, PutBucketVersioningOutput,
    },
};

#[derive(Clone)]
pub struct BucketsService {
    client: Client,
}

impl BucketsService {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn list(&self) -> ListBucketsRequest {
        ListBucketsRequest {
            client: self.client.clone(),
        }
    }

    pub fn head(&self, bucket: impl Into<String>) -> HeadBucketRequest {
        HeadBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn create(&self, bucket: impl Into<String>) -> CreateBucketRequest {
        CreateBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            location_constraint: None,
        }
    }

    pub fn delete(&self, bucket: impl Into<String>) -> DeleteBucketRequest {
        DeleteBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_versioning(&self, bucket: impl Into<String>) -> GetBucketVersioningRequest {
        GetBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_versioning(&self, bucket: impl Into<String>) -> PutBucketVersioningRequest {
        PutBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketVersioningConfiguration::default(),
        }
    }

    pub fn get_lifecycle(&self, bucket: impl Into<String>) -> GetBucketLifecycleRequest {
        GetBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_lifecycle(&self, bucket: impl Into<String>) -> PutBucketLifecycleRequest {
        PutBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketLifecycleConfiguration::default(),
        }
    }

    pub fn delete_lifecycle(&self, bucket: impl Into<String>) -> DeleteBucketLifecycleRequest {
        DeleteBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_cors(&self, bucket: impl Into<String>) -> GetBucketCorsRequest {
        GetBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_cors(&self, bucket: impl Into<String>) -> PutBucketCorsRequest {
        PutBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketCorsConfiguration::default(),
        }
    }

    pub fn delete_cors(&self, bucket: impl Into<String>) -> DeleteBucketCorsRequest {
        DeleteBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_tagging(&self, bucket: impl Into<String>) -> GetBucketTaggingRequest {
        GetBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_tagging(&self, bucket: impl Into<String>) -> PutBucketTaggingRequest {
        PutBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            tagging: BucketTagging::default(),
        }
    }

    pub fn delete_tagging(&self, bucket: impl Into<String>) -> DeleteBucketTaggingRequest {
        DeleteBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_encryption(&self, bucket: impl Into<String>) -> GetBucketEncryptionRequest {
        GetBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_encryption(&self, bucket: impl Into<String>) -> PutBucketEncryptionRequest {
        PutBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketEncryptionConfiguration::default(),
        }
    }

    pub fn delete_encryption(&self, bucket: impl Into<String>) -> DeleteBucketEncryptionRequest {
        DeleteBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> GetBucketPublicAccessBlockRequest {
        GetBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> PutBucketPublicAccessBlockRequest {
        PutBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketPublicAccessBlockConfiguration::default(),
        }
    }

    pub fn delete_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> DeleteBucketPublicAccessBlockRequest {
        DeleteBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_config_raw(
        &self,
        bucket: impl Into<String>,
        subresource: impl Into<String>,
    ) -> GetBucketConfigRawRequest {
        GetBucketConfigRawRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            subresource: subresource.into(),
        }
    }

    pub fn put_config_raw(
        &self,
        bucket: impl Into<String>,
        subresource: impl Into<String>,
    ) -> PutBucketConfigRawRequest {
        PutBucketConfigRawRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            subresource: subresource.into(),
            body: Bytes::new(),
        }
    }

    pub fn delete_config_raw(
        &self,
        bucket: impl Into<String>,
        subresource: impl Into<String>,
    ) -> DeleteBucketConfigRawRequest {
        DeleteBucketConfigRawRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            subresource: subresource.into(),
        }
    }
}

pub struct ListBucketsRequest {
    client: Client,
}

impl ListBucketsRequest {
    pub async fn send(self) -> Result<ListBucketsOutput> {
        let resp = self
            .client
            .execute(
                Method::GET,
                None,
                None,
                Vec::new(),
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_list_buckets(&xml)
    }
}

pub struct HeadBucketRequest {
    client: Client,
    bucket: String,
}

impl HeadBucketRequest {
    pub async fn send(self) -> Result<HeadBucketOutput> {
        let resp = self
            .client
            .execute(
                Method::HEAD,
                Some(&self.bucket),
                None,
                Vec::new(),
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        Ok(HeadBucketOutput {
            region: header_string(&resp, "x-amz-bucket-region"),
        })
    }
}

pub struct CreateBucketRequest {
    client: Client,
    bucket: String,
    location_constraint: Option<String>,
}

impl CreateBucketRequest {
    pub fn location_constraint(mut self, region: impl Into<String>) -> Self {
        self.location_constraint = Some(region.into());
        self
    }

    pub async fn send(self) -> Result<CreateBucketOutput> {
        let mut headers = HeaderMap::new();
        let body = match self.location_constraint {
            Some(region) => {
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                );
                AsyncBody::Bytes(crate::util::xml::encode_create_bucket_configuration(
                    &region,
                )?)
            }
            None => AsyncBody::Empty,
        };

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                Vec::new(),
                headers,
                body,
            )
            .await?;

        if resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT {
            return Ok(CreateBucketOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketRequest {
    pub async fn send(self) -> Result<DeleteBucketOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                Vec::new(),
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketVersioningRequest {
    client: Client,
    bucket: String,
}

impl GetBucketVersioningRequest {
    pub async fn send(self) -> Result<BucketVersioningConfiguration> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("versioning".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_versioning(&xml)
    }
}

pub struct PutBucketVersioningRequest {
    client: Client,
    bucket: String,
    configuration: BucketVersioningConfiguration,
}

impl PutBucketVersioningRequest {
    pub fn configuration(mut self, value: BucketVersioningConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketVersioningOutput> {
        let body = crate::util::xml::encode_bucket_versioning(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("versioning".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketVersioningOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketLifecycleRequest {
    client: Client,
    bucket: String,
}

impl GetBucketLifecycleRequest {
    pub async fn send(self) -> Result<BucketLifecycleConfiguration> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("lifecycle".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_lifecycle(&xml)
    }
}

pub struct PutBucketLifecycleRequest {
    client: Client,
    bucket: String,
    configuration: BucketLifecycleConfiguration,
}

impl PutBucketLifecycleRequest {
    pub fn configuration(mut self, value: BucketLifecycleConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketLifecycleOutput> {
        let body = crate::util::xml::encode_bucket_lifecycle(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("lifecycle".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketLifecycleOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketLifecycleRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketLifecycleRequest {
    pub async fn send(self) -> Result<DeleteBucketLifecycleOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![("lifecycle".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketLifecycleOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketCorsRequest {
    client: Client,
    bucket: String,
}

impl GetBucketCorsRequest {
    pub async fn send(self) -> Result<BucketCorsConfiguration> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("cors".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_cors(&xml)
    }
}

pub struct PutBucketCorsRequest {
    client: Client,
    bucket: String,
    configuration: BucketCorsConfiguration,
}

impl PutBucketCorsRequest {
    pub fn configuration(mut self, value: BucketCorsConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketCorsOutput> {
        let body = crate::util::xml::encode_bucket_cors(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("cors".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketCorsOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketCorsRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketCorsRequest {
    pub async fn send(self) -> Result<DeleteBucketCorsOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![("cors".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketCorsOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketTaggingRequest {
    client: Client,
    bucket: String,
}

impl GetBucketTaggingRequest {
    pub async fn send(self) -> Result<BucketTagging> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("tagging".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_tagging(&xml)
    }
}

pub struct PutBucketTaggingRequest {
    client: Client,
    bucket: String,
    tagging: BucketTagging,
}

impl PutBucketTaggingRequest {
    pub fn tagging(mut self, value: BucketTagging) -> Self {
        self.tagging = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketTaggingOutput> {
        let body = crate::util::xml::encode_bucket_tagging(&self.tagging)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("tagging".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketTaggingOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketTaggingRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketTaggingRequest {
    pub async fn send(self) -> Result<DeleteBucketTaggingOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![("tagging".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketTaggingOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketEncryptionRequest {
    client: Client,
    bucket: String,
}

impl GetBucketEncryptionRequest {
    pub async fn send(self) -> Result<BucketEncryptionConfiguration> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("encryption".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_encryption(&xml)
    }
}

pub struct PutBucketEncryptionRequest {
    client: Client,
    bucket: String,
    configuration: BucketEncryptionConfiguration,
}

impl PutBucketEncryptionRequest {
    pub fn configuration(mut self, value: BucketEncryptionConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketEncryptionOutput> {
        let body = crate::util::xml::encode_bucket_encryption(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("encryption".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketEncryptionOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketEncryptionRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketEncryptionRequest {
    pub async fn send(self) -> Result<DeleteBucketEncryptionOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![("encryption".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketEncryptionOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct GetBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
}

impl GetBucketPublicAccessBlockRequest {
    pub async fn send(self) -> Result<BucketPublicAccessBlockConfiguration> {
        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![("publicAccessBlock".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        let xml = resp
            .text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        crate::util::xml::parse_bucket_public_access_block(&xml)
    }
}

pub struct PutBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
    configuration: BucketPublicAccessBlockConfiguration,
}

impl PutBucketPublicAccessBlockRequest {
    pub fn configuration(mut self, value: BucketPublicAccessBlockConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub async fn send(self) -> Result<PutBucketPublicAccessBlockOutput> {
        let body = crate::util::xml::encode_bucket_public_access_block(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![("publicAccessBlock".to_string(), String::new())],
                headers,
                AsyncBody::Bytes(body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(PutBucketPublicAccessBlockOutput);
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketPublicAccessBlockRequest {
    pub async fn send(self) -> Result<DeleteBucketPublicAccessBlockOutput> {
        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![("publicAccessBlock".to_string(), String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketPublicAccessBlockOutput);
        }

        Err(response_error(resp).await)
    }
}

fn header_string(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

pub struct GetBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
}

impl GetBucketConfigRawRequest {
    pub async fn send(self) -> Result<String> {
        validate_subresource(&self.subresource)?;

        let resp = self
            .client
            .execute(
                Method::GET,
                Some(&self.bucket),
                None,
                vec![(self.subresource, String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if !resp.status().is_success() {
            return Err(response_error(resp).await);
        }

        resp.text()
            .await
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))
    }
}

pub struct PutBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
    body: Bytes,
}

impl PutBucketConfigRawRequest {
    pub fn body_xml(mut self, xml: impl Into<String>) -> Self {
        self.body = Bytes::from(xml.into());
        self
    }

    pub fn body_bytes(mut self, bytes: impl Into<Bytes>) -> Self {
        self.body = bytes.into();
        self
    }

    pub async fn send(self) -> Result<()> {
        validate_subresource(&self.subresource)?;
        if self.body.is_empty() {
            return Err(Error::invalid_config(
                "put_config_raw requires a request body",
            ));
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self
            .client
            .execute(
                Method::PUT,
                Some(&self.bucket),
                None,
                vec![(self.subresource, String::new())],
                headers,
                AsyncBody::Bytes(self.body),
            )
            .await?;

        if resp.status().is_success() {
            return Ok(());
        }

        Err(response_error(resp).await)
    }
}

pub struct DeleteBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
}

impl DeleteBucketConfigRawRequest {
    pub async fn send(self) -> Result<()> {
        validate_subresource(&self.subresource)?;

        let resp = self
            .client
            .execute(
                Method::DELETE,
                Some(&self.bucket),
                None,
                vec![(self.subresource, String::new())],
                HeaderMap::new(),
                AsyncBody::Empty,
            )
            .await?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(());
        }

        Err(response_error(resp).await)
    }
}

fn validate_subresource(subresource: &str) -> Result<()> {
    if subresource.trim().is_empty() {
        return Err(Error::invalid_config("subresource must not be empty"));
    }
    Ok(())
}
