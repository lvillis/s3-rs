use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::blocking_common::read_body_string;

use crate::{
    client::BlockingClient,
    error::{Error, Result},
    transport::blocking_transport::{BlockingBody, response_error},
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
pub struct BlockingBucketsService {
    client: BlockingClient,
}

impl BlockingBucketsService {
    pub(crate) fn new(client: BlockingClient) -> Self {
        Self { client }
    }

    pub fn list(&self) -> BlockingListBucketsRequest {
        BlockingListBucketsRequest {
            client: self.client.clone(),
        }
    }

    pub fn head(&self, bucket: impl Into<String>) -> BlockingHeadBucketRequest {
        BlockingHeadBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn create(&self, bucket: impl Into<String>) -> BlockingCreateBucketRequest {
        BlockingCreateBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            location_constraint: None,
        }
    }

    pub fn delete(&self, bucket: impl Into<String>) -> BlockingDeleteBucketRequest {
        BlockingDeleteBucketRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_versioning(&self, bucket: impl Into<String>) -> BlockingGetBucketVersioningRequest {
        BlockingGetBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_versioning(&self, bucket: impl Into<String>) -> BlockingPutBucketVersioningRequest {
        BlockingPutBucketVersioningRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketVersioningConfiguration::default(),
        }
    }

    pub fn get_lifecycle(&self, bucket: impl Into<String>) -> BlockingGetBucketLifecycleRequest {
        BlockingGetBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_lifecycle(&self, bucket: impl Into<String>) -> BlockingPutBucketLifecycleRequest {
        BlockingPutBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketLifecycleConfiguration::default(),
        }
    }

    pub fn delete_lifecycle(
        &self,
        bucket: impl Into<String>,
    ) -> BlockingDeleteBucketLifecycleRequest {
        BlockingDeleteBucketLifecycleRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_cors(&self, bucket: impl Into<String>) -> BlockingGetBucketCorsRequest {
        BlockingGetBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_cors(&self, bucket: impl Into<String>) -> BlockingPutBucketCorsRequest {
        BlockingPutBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketCorsConfiguration::default(),
        }
    }

    pub fn delete_cors(&self, bucket: impl Into<String>) -> BlockingDeleteBucketCorsRequest {
        BlockingDeleteBucketCorsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_tagging(&self, bucket: impl Into<String>) -> BlockingGetBucketTaggingRequest {
        BlockingGetBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_tagging(&self, bucket: impl Into<String>) -> BlockingPutBucketTaggingRequest {
        BlockingPutBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            tagging: BucketTagging::default(),
        }
    }

    pub fn delete_tagging(&self, bucket: impl Into<String>) -> BlockingDeleteBucketTaggingRequest {
        BlockingDeleteBucketTaggingRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_encryption(&self, bucket: impl Into<String>) -> BlockingGetBucketEncryptionRequest {
        BlockingGetBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_encryption(&self, bucket: impl Into<String>) -> BlockingPutBucketEncryptionRequest {
        BlockingPutBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketEncryptionConfiguration::default(),
        }
    }

    pub fn delete_encryption(
        &self,
        bucket: impl Into<String>,
    ) -> BlockingDeleteBucketEncryptionRequest {
        BlockingDeleteBucketEncryptionRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> BlockingGetBucketPublicAccessBlockRequest {
        BlockingGetBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn put_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> BlockingPutBucketPublicAccessBlockRequest {
        BlockingPutBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            configuration: BucketPublicAccessBlockConfiguration::default(),
        }
    }

    pub fn delete_public_access_block(
        &self,
        bucket: impl Into<String>,
    ) -> BlockingDeleteBucketPublicAccessBlockRequest {
        BlockingDeleteBucketPublicAccessBlockRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
        }
    }

    pub fn get_config_raw(
        &self,
        bucket: impl Into<String>,
        subresource: impl Into<String>,
    ) -> BlockingGetBucketConfigRawRequest {
        BlockingGetBucketConfigRawRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            subresource: subresource.into(),
        }
    }

    pub fn put_config_raw(
        &self,
        bucket: impl Into<String>,
        subresource: impl Into<String>,
    ) -> BlockingPutBucketConfigRawRequest {
        BlockingPutBucketConfigRawRequest {
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
    ) -> BlockingDeleteBucketConfigRawRequest {
        BlockingDeleteBucketConfigRawRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            subresource: subresource.into(),
        }
    }
}

pub struct BlockingListBucketsRequest {
    client: BlockingClient,
}

impl BlockingListBucketsRequest {
    pub fn send(self) -> Result<ListBucketsOutput> {
        let resp = self.client.execute(
            Method::GET,
            None,
            None,
            Vec::new(),
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_list_buckets(&xml)
    }
}

pub struct BlockingHeadBucketRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingHeadBucketRequest {
    pub fn send(self) -> Result<HeadBucketOutput> {
        let resp = self.client.execute(
            Method::HEAD,
            Some(&self.bucket),
            None,
            Vec::new(),
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        Ok(HeadBucketOutput {
            region: crate::util::headers::header_string(resp.headers(), "x-amz-bucket-region"),
        })
    }
}

pub struct BlockingCreateBucketRequest {
    client: BlockingClient,
    bucket: String,
    location_constraint: Option<String>,
}

impl BlockingCreateBucketRequest {
    pub fn location_constraint(mut self, region: impl Into<String>) -> Self {
        self.location_constraint = Some(region.into());
        self
    }

    pub fn send(self) -> Result<CreateBucketOutput> {
        let mut headers = HeaderMap::new();
        let body = match self.location_constraint {
            Some(region) => {
                headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/xml"),
                );
                BlockingBody::Bytes(crate::util::xml::encode_create_bucket_configuration(
                    &region,
                )?)
            }
            None => BlockingBody::Empty,
        };

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            Vec::new(),
            headers,
            body,
        )?;

        if resp.status() == StatusCode::OK || resp.status() == StatusCode::NO_CONTENT {
            return Ok(CreateBucketOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketRequest {
    pub fn send(self) -> Result<DeleteBucketOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            Vec::new(),
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketVersioningRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketVersioningRequest {
    pub fn send(self) -> Result<BucketVersioningConfiguration> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("versioning".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_versioning(&xml)
    }
}

pub struct BlockingPutBucketVersioningRequest {
    client: BlockingClient,
    bucket: String,
    configuration: BucketVersioningConfiguration,
}

impl BlockingPutBucketVersioningRequest {
    pub fn configuration(mut self, value: BucketVersioningConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub fn send(self) -> Result<PutBucketVersioningOutput> {
        let body = crate::util::xml::encode_bucket_versioning(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("versioning".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketVersioningOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketLifecycleRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketLifecycleRequest {
    pub fn send(self) -> Result<BucketLifecycleConfiguration> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("lifecycle".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_lifecycle(&xml)
    }
}

pub struct BlockingPutBucketLifecycleRequest {
    client: BlockingClient,
    bucket: String,
    configuration: BucketLifecycleConfiguration,
}

impl BlockingPutBucketLifecycleRequest {
    pub fn configuration(mut self, value: BucketLifecycleConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub fn send(self) -> Result<PutBucketLifecycleOutput> {
        let body = crate::util::xml::encode_bucket_lifecycle(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("lifecycle".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketLifecycleOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketLifecycleRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketLifecycleRequest {
    pub fn send(self) -> Result<DeleteBucketLifecycleOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![("lifecycle".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketLifecycleOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketCorsRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketCorsRequest {
    pub fn send(self) -> Result<BucketCorsConfiguration> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("cors".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_cors(&xml)
    }
}

pub struct BlockingPutBucketCorsRequest {
    client: BlockingClient,
    bucket: String,
    configuration: BucketCorsConfiguration,
}

impl BlockingPutBucketCorsRequest {
    pub fn configuration(mut self, value: BucketCorsConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub fn send(self) -> Result<PutBucketCorsOutput> {
        let body = crate::util::xml::encode_bucket_cors(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("cors".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketCorsOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketCorsRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketCorsRequest {
    pub fn send(self) -> Result<DeleteBucketCorsOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![("cors".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketCorsOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketTaggingRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketTaggingRequest {
    pub fn send(self) -> Result<BucketTagging> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("tagging".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_tagging(&xml)
    }
}

pub struct BlockingPutBucketTaggingRequest {
    client: BlockingClient,
    bucket: String,
    tagging: BucketTagging,
}

impl BlockingPutBucketTaggingRequest {
    pub fn tagging(mut self, value: BucketTagging) -> Self {
        self.tagging = value;
        self
    }

    pub fn send(self) -> Result<PutBucketTaggingOutput> {
        let body = crate::util::xml::encode_bucket_tagging(&self.tagging)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("tagging".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketTaggingOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketTaggingRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketTaggingRequest {
    pub fn send(self) -> Result<DeleteBucketTaggingOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![("tagging".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketTaggingOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketEncryptionRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketEncryptionRequest {
    pub fn send(self) -> Result<BucketEncryptionConfiguration> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("encryption".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_encryption(&xml)
    }
}

pub struct BlockingPutBucketEncryptionRequest {
    client: BlockingClient,
    bucket: String,
    configuration: BucketEncryptionConfiguration,
}

impl BlockingPutBucketEncryptionRequest {
    pub fn configuration(mut self, value: BucketEncryptionConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub fn send(self) -> Result<PutBucketEncryptionOutput> {
        let body = crate::util::xml::encode_bucket_encryption(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("encryption".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketEncryptionOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketEncryptionRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketEncryptionRequest {
    pub fn send(self) -> Result<DeleteBucketEncryptionOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![("encryption".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketEncryptionOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketPublicAccessBlockRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingGetBucketPublicAccessBlockRequest {
    pub fn send(self) -> Result<BucketPublicAccessBlockConfiguration> {
        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![("publicAccessBlock".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_bucket_public_access_block(&xml)
    }
}

pub struct BlockingPutBucketPublicAccessBlockRequest {
    client: BlockingClient,
    bucket: String,
    configuration: BucketPublicAccessBlockConfiguration,
}

impl BlockingPutBucketPublicAccessBlockRequest {
    pub fn configuration(mut self, value: BucketPublicAccessBlockConfiguration) -> Self {
        self.configuration = value;
        self
    }

    pub fn send(self) -> Result<PutBucketPublicAccessBlockOutput> {
        let body = crate::util::xml::encode_bucket_public_access_block(&self.configuration)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![("publicAccessBlock".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if resp.status().is_success() {
            return Ok(PutBucketPublicAccessBlockOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketPublicAccessBlockRequest {
    client: BlockingClient,
    bucket: String,
}

impl BlockingDeleteBucketPublicAccessBlockRequest {
    pub fn send(self) -> Result<DeleteBucketPublicAccessBlockOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![("publicAccessBlock".to_string(), String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(DeleteBucketPublicAccessBlockOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingGetBucketConfigRawRequest {
    client: BlockingClient,
    bucket: String,
    subresource: String,
}

impl BlockingGetBucketConfigRawRequest {
    pub fn send(self) -> Result<String> {
        validate_subresource(&self.subresource)?;

        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            vec![(self.subresource, String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        read_body_string(body)
    }
}

pub struct BlockingPutBucketConfigRawRequest {
    client: BlockingClient,
    bucket: String,
    subresource: String,
    body: Bytes,
}

impl BlockingPutBucketConfigRawRequest {
    pub fn body_xml(mut self, xml: impl Into<String>) -> Self {
        self.body = Bytes::from(xml.into());
        self
    }

    pub fn body_bytes(mut self, bytes: impl Into<Bytes>) -> Self {
        self.body = bytes.into();
        self
    }

    pub fn send(self) -> Result<()> {
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

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            None,
            vec![(self.subresource, String::new())],
            headers,
            BlockingBody::Bytes(self.body),
        )?;

        if resp.status().is_success() {
            return Ok(());
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteBucketConfigRawRequest {
    client: BlockingClient,
    bucket: String,
    subresource: String,
}

impl BlockingDeleteBucketConfigRawRequest {
    pub fn send(self) -> Result<()> {
        validate_subresource(&self.subresource)?;

        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            None,
            vec![(self.subresource, String::new())],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(());
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

fn validate_subresource(subresource: &str) -> Result<()> {
    if subresource.trim().is_empty() {
        return Err(Error::invalid_config("subresource must not be empty"));
    }
    Ok(())
}
