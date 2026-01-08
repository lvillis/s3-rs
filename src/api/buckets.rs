//! Async bucket operations.

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

/// Bucket operations service.
#[derive(Clone)]
pub struct BucketsService {
    client: Client,
}

impl BucketsService {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }

    /// Starts a request to list buckets.
    pub fn list(&self) -> ListBucketsRequest {
        ListBucketsRequest {
            client: self.client.clone(),
        }
    }

    /// Starts a request to check if a bucket exists.
    pub fn head(&self, bucket: impl Into<String>) -> HeadBucketRequest {
        HeadBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to create a bucket.
    pub fn create(&self, bucket: impl Into<String>) -> CreateBucketRequest {
        CreateBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            location_constraint: None,
        }
    }

    /// Starts a request to delete a bucket.
    pub fn delete(&self, bucket: impl Into<String>) -> DeleteBucketRequest {
        DeleteBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to get bucket versioning.
    pub fn get_versioning(&self, bucket: impl Into<String>) -> GetBucketVersioningRequest {
        GetBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set bucket versioning.
    pub fn put_versioning(&self, bucket: impl Into<String>) -> PutBucketVersioningRequest {
        PutBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketVersioningConfiguration::default(),
        }
    }

    /// Starts a request to get bucket lifecycle configuration.
    pub fn get_lifecycle(&self, bucket: impl Into<String>) -> GetBucketLifecycleRequest {
        GetBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set bucket lifecycle configuration.
    pub fn put_lifecycle(&self, bucket: impl Into<String>) -> PutBucketLifecycleRequest {
        PutBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketLifecycleConfiguration::default(),
        }
    }

    /// Starts a request to delete bucket lifecycle configuration.
    pub fn delete_lifecycle(&self, bucket: impl Into<String>) -> DeleteBucketLifecycleRequest {
        DeleteBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to get bucket CORS rules.
    pub fn get_cors(&self, bucket: impl Into<String>) -> GetBucketCorsRequest {
        GetBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set bucket CORS rules.
    pub fn put_cors(&self, bucket: impl Into<String>) -> PutBucketCorsRequest {
        PutBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketCorsConfiguration::default(),
        }
    }

    /// Starts a request to delete bucket CORS rules.
    pub fn delete_cors(&self, bucket: impl Into<String>) -> DeleteBucketCorsRequest {
        DeleteBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to get bucket tags.
    pub fn get_tagging(&self, bucket: impl Into<String>) -> GetBucketTaggingRequest {
        GetBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set bucket tags.
    pub fn put_tagging(&self, bucket: impl Into<String>) -> PutBucketTaggingRequest {
        PutBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            tagging: BucketTagging::default(),
        }
    }

    /// Starts a request to delete bucket tags.
    pub fn delete_tagging(&self, bucket: impl Into<String>) -> DeleteBucketTaggingRequest {
        DeleteBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to get bucket encryption configuration.
    pub fn get_encryption(&self, bucket: impl Into<String>) -> GetBucketEncryptionRequest {
        GetBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set bucket encryption configuration.
    pub fn put_encryption(&self, bucket: impl Into<String>) -> PutBucketEncryptionRequest {
        PutBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketEncryptionConfiguration::default(),
        }
    }

    /// Starts a request to delete bucket encryption configuration.
    pub fn delete_encryption(&self, bucket: impl Into<String>) -> DeleteBucketEncryptionRequest {
        DeleteBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to get public access block settings.
    pub fn get_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> GetBucketPublicAccessBlockRequest {
        GetBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to set public access block settings.
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

    /// Starts a request to delete public access block settings.
    pub fn delete_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> DeleteBucketPublicAccessBlockRequest {
        DeleteBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    /// Starts a request to read a raw bucket config subresource.
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

    /// Starts a request to write a raw bucket config subresource.
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

    /// Starts a request to delete a raw bucket config subresource.
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

/// Request builder for listing buckets.
pub struct ListBucketsRequest {
    client: Client,
}

impl ListBucketsRequest {
    /// Sends the request.
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

/// Request builder for checking bucket existence.
pub struct HeadBucketRequest {
    client: Client,
    bucket: String,
}

impl HeadBucketRequest {
    /// Sends the request.
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
            region: crate::util::headers::header_string(resp.headers(), "x-amz-bucket-region"),
        })
    }
}

/// Request builder for creating a bucket.
pub struct CreateBucketRequest {
    client: Client,
    bucket: String,
    location_constraint: Option<String>,
}

impl CreateBucketRequest {
    /// Sets the location constraint for bucket creation.
    pub fn location_constraint(mut self, region: impl Into<String>) -> Self {
        self.location_constraint = Some(region.into());
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<CreateBucketOutput> {
        let mut headers = HeaderMap::new();
        let body = match self.location_constraint {
            Some(region) => {
                let body = crate::util::xml::encode_create_bucket_configuration(&region)?;
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                );
                headers.insert(
                    http::header::HeaderName::from_static("content-md5"),
                    crate::util::md5::content_md5_header_value(body.as_ref())?,
                );
                AsyncBody::Bytes(body)
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

/// Request builder for deleting a bucket.
pub struct DeleteBucketRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketRequest {
    /// Sends the request.
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

/// Request builder for reading bucket versioning settings.
pub struct GetBucketVersioningRequest {
    client: Client,
    bucket: String,
}

impl GetBucketVersioningRequest {
    /// Sends the request.
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

/// Request builder for updating bucket versioning settings.
pub struct PutBucketVersioningRequest {
    client: Client,
    bucket: String,
    configuration: BucketVersioningConfiguration,
}

impl PutBucketVersioningRequest {
    /// Sets the versioning configuration to apply.
    pub fn configuration(mut self, value: BucketVersioningConfiguration) -> Self {
        self.configuration = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketVersioningOutput> {
        let body = crate::util::xml::encode_bucket_versioning(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for reading bucket lifecycle configuration.
pub struct GetBucketLifecycleRequest {
    client: Client,
    bucket: String,
}

impl GetBucketLifecycleRequest {
    /// Sends the request.
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

/// Request builder for updating bucket lifecycle configuration.
pub struct PutBucketLifecycleRequest {
    client: Client,
    bucket: String,
    configuration: BucketLifecycleConfiguration,
}

impl PutBucketLifecycleRequest {
    /// Sets the lifecycle configuration to apply.
    pub fn configuration(mut self, value: BucketLifecycleConfiguration) -> Self {
        self.configuration = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketLifecycleOutput> {
        let body = crate::util::xml::encode_bucket_lifecycle(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for deleting bucket lifecycle configuration.
pub struct DeleteBucketLifecycleRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketLifecycleRequest {
    /// Sends the request.
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

/// Request builder for reading bucket CORS configuration.
pub struct GetBucketCorsRequest {
    client: Client,
    bucket: String,
}

impl GetBucketCorsRequest {
    /// Sends the request.
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

/// Request builder for updating bucket CORS configuration.
pub struct PutBucketCorsRequest {
    client: Client,
    bucket: String,
    configuration: BucketCorsConfiguration,
}

impl PutBucketCorsRequest {
    /// Sets the CORS configuration to apply.
    pub fn configuration(mut self, value: BucketCorsConfiguration) -> Self {
        self.configuration = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketCorsOutput> {
        let body = crate::util::xml::encode_bucket_cors(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for deleting bucket CORS configuration.
pub struct DeleteBucketCorsRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketCorsRequest {
    /// Sends the request.
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

/// Request builder for reading bucket tags.
pub struct GetBucketTaggingRequest {
    client: Client,
    bucket: String,
}

impl GetBucketTaggingRequest {
    /// Sends the request.
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

/// Request builder for updating bucket tags.
pub struct PutBucketTaggingRequest {
    client: Client,
    bucket: String,
    tagging: BucketTagging,
}

impl PutBucketTaggingRequest {
    /// Sets the tag set to apply.
    pub fn tagging(mut self, value: BucketTagging) -> Self {
        self.tagging = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketTaggingOutput> {
        let body = crate::util::xml::encode_bucket_tagging(&self.tagging)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for deleting bucket tags.
pub struct DeleteBucketTaggingRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketTaggingRequest {
    /// Sends the request.
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

/// Request builder for reading bucket encryption configuration.
pub struct GetBucketEncryptionRequest {
    client: Client,
    bucket: String,
}

impl GetBucketEncryptionRequest {
    /// Sends the request.
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

/// Request builder for updating bucket encryption configuration.
pub struct PutBucketEncryptionRequest {
    client: Client,
    bucket: String,
    configuration: BucketEncryptionConfiguration,
}

impl PutBucketEncryptionRequest {
    /// Sets the encryption configuration to apply.
    pub fn configuration(mut self, value: BucketEncryptionConfiguration) -> Self {
        self.configuration = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketEncryptionOutput> {
        let body = crate::util::xml::encode_bucket_encryption(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for deleting bucket encryption configuration.
pub struct DeleteBucketEncryptionRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketEncryptionRequest {
    /// Sends the request.
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

/// Request builder for reading public access block settings.
pub struct GetBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
}

impl GetBucketPublicAccessBlockRequest {
    /// Sends the request.
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

/// Request builder for updating public access block settings.
pub struct PutBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
    configuration: BucketPublicAccessBlockConfiguration,
}

impl PutBucketPublicAccessBlockRequest {
    /// Sets the public access block configuration to apply.
    pub fn configuration(mut self, value: BucketPublicAccessBlockConfiguration) -> Self {
        self.configuration = value;
        self
    }

    /// Sends the request.
    pub async fn send(self) -> Result<PutBucketPublicAccessBlockOutput> {
        let body = crate::util::xml::encode_bucket_public_access_block(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(body.as_ref())?,
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

/// Request builder for deleting public access block settings.
pub struct DeleteBucketPublicAccessBlockRequest {
    client: Client,
    bucket: String,
}

impl DeleteBucketPublicAccessBlockRequest {
    /// Sends the request.
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

/// Request builder for fetching raw bucket config XML.
pub struct GetBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
}

impl GetBucketConfigRawRequest {
    /// Sends the request.
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

/// Request builder for writing raw bucket config XML.
pub struct PutBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
    body: Bytes,
}

impl PutBucketConfigRawRequest {
    /// Sets the request body from an XML string.
    pub fn body_xml(mut self, xml: impl Into<String>) -> Self {
        self.body = Bytes::from(xml.into());
        self
    }

    /// Sets the request body from raw bytes.
    pub fn body_bytes(mut self, bytes: impl Into<Bytes>) -> Self {
        self.body = bytes.into();
        self
    }

    /// Sends the request.
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
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            crate::util::md5::content_md5_header_value(self.body.as_ref())?,
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

/// Request builder for deleting raw bucket config.
pub struct DeleteBucketConfigRawRequest {
    client: Client,
    bucket: String,
    subresource: String,
}

impl DeleteBucketConfigRawRequest {
    /// Sends the request.
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
