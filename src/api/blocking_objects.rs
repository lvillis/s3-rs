use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::blocking_common::read_body_string;

use crate::{
    client::BlockingClient,
    error::{Error, Result},
    transport::blocking_transport::{BlockingBody, response_error},
    types::{
        BlockingByteStream, BlockingGetObjectOutput, CopyObjectOutput, DeleteObjectIdentifier,
        DeleteObjectsOutput, HeadObjectOutput, ListObjectsV2Output, PresignedRequest,
        PutObjectOutput,
    },
};

#[cfg(feature = "multipart")]
use crate::types::{
    AbortMultipartUploadOutput, CompleteMultipartUploadOutput, CompletedPart,
    CreateMultipartUploadOutput, ListPartsOutput, UploadPartCopyOutput, UploadPartOutput,
};

#[derive(Clone)]
pub struct BlockingObjectsService {
    client: BlockingClient,
}

impl BlockingObjectsService {
    pub(crate) fn new(client: BlockingClient) -> Self {
        Self { client }
    }

    pub fn get(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingGetObjectRequest {
        BlockingGetObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            range: None,
            if_match: None,
            if_none_match: None,
            if_modified_since: None,
            if_unmodified_since: None,
        }
    }

    pub fn head(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingHeadObjectRequest {
        BlockingHeadObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
        }
    }

    pub fn put(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPutObjectRequest {
        BlockingPutObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            content_type: None,
            cache_control: None,
            content_disposition: None,
            content_encoding: None,
            content_language: None,
            expires: None,
            #[cfg(feature = "checksums")]
            checksum: None,
            metadata: Vec::new(),
            body: BlockingBody::Empty,
        }
    }

    pub fn delete(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingDeleteObjectRequest {
        BlockingDeleteObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
        }
    }

    pub fn delete_objects(&self, bucket: impl Into<String>) -> BlockingDeleteObjectsRequest {
        BlockingDeleteObjectsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            objects: Vec::new(),
            quiet: false,
        }
    }

    pub fn copy(
        &self,
        source_bucket: impl Into<String>,
        source_key: impl Into<String>,
        destination_bucket: impl Into<String>,
        destination_key: impl Into<String>,
    ) -> BlockingCopyObjectRequest {
        BlockingCopyObjectRequest {
            client: self.client.clone(),
            source_bucket: source_bucket.into(),
            source_key: source_key.into(),
            source_version_id: None,
            destination_bucket: destination_bucket.into(),
            destination_key: destination_key.into(),
            metadata_directive: None,
            metadata: Vec::new(),
            content_type: None,
        }
    }

    #[cfg(feature = "multipart")]
    pub fn create_multipart_upload(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingCreateMultipartUploadRequest {
        BlockingCreateMultipartUploadRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            content_type: None,
            metadata: Vec::new(),
        }
    }

    #[cfg(feature = "multipart")]
    pub fn upload_part(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
        part_number: u32,
    ) -> BlockingUploadPartRequest {
        BlockingUploadPartRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            upload_id: upload_id.into(),
            part_number,
            body: BlockingBody::Empty,
        }
    }

    #[cfg(feature = "multipart")]
    pub fn upload_part_copy(
        &self,
        source_bucket: impl Into<String>,
        source_key: impl Into<String>,
        destination_bucket: impl Into<String>,
        destination_key: impl Into<String>,
        upload_id: impl Into<String>,
        part_number: u32,
    ) -> BlockingUploadPartCopyRequest {
        BlockingUploadPartCopyRequest {
            client: self.client.clone(),
            source_bucket: source_bucket.into(),
            source_key: source_key.into(),
            source_version_id: None,
            destination_bucket: destination_bucket.into(),
            destination_key: destination_key.into(),
            upload_id: upload_id.into(),
            part_number,
            copy_source_range: None,
        }
    }

    #[cfg(feature = "multipart")]
    pub fn complete_multipart_upload(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
    ) -> BlockingCompleteMultipartUploadRequest {
        BlockingCompleteMultipartUploadRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            upload_id: upload_id.into(),
            parts: Vec::new(),
        }
    }

    #[cfg(feature = "multipart")]
    pub fn abort_multipart_upload(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
    ) -> BlockingAbortMultipartUploadRequest {
        BlockingAbortMultipartUploadRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            upload_id: upload_id.into(),
        }
    }

    #[cfg(feature = "multipart")]
    pub fn list_parts(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
    ) -> BlockingListPartsRequest {
        BlockingListPartsRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            upload_id: upload_id.into(),
            max_parts: None,
            part_number_marker: None,
        }
    }

    pub fn list_v2(&self, bucket: impl Into<String>) -> BlockingListObjectsV2Request {
        BlockingListObjectsV2Request {
            client: self.client.clone(),
            bucket: bucket.into(),
            prefix: None,
            delimiter: None,
            continuation_token: None,
            start_after: None,
            max_keys: None,
        }
    }

    pub fn presign(
        &self,
        method: Method,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPresignObjectRequest {
        BlockingPresignObjectRequest {
            client: self.client.clone(),
            method,
            bucket: bucket.into(),
            key: key.into(),
            expires_in: Duration::from_secs(900),
            query_params: Vec::new(),
            headers: HeaderMap::new(),
            metadata: Vec::new(),
        }
    }

    pub fn presign_get(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPresignGetObjectRequest {
        BlockingPresignGetObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            expires_in: Duration::from_secs(900),
            query_params: Vec::new(),
            headers: HeaderMap::new(),
            metadata: Vec::new(),
        }
    }

    pub fn presign_put(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPresignPutObjectRequest {
        BlockingPresignPutObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            expires_in: Duration::from_secs(900),
            query_params: Vec::new(),
            headers: HeaderMap::new(),
            metadata: Vec::new(),
        }
    }

    pub fn presign_head(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPresignHeadObjectRequest {
        BlockingPresignHeadObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            expires_in: Duration::from_secs(900),
            query_params: Vec::new(),
            headers: HeaderMap::new(),
        }
    }

    pub fn presign_delete(
        &self,
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> BlockingPresignDeleteObjectRequest {
        BlockingPresignDeleteObjectRequest {
            client: self.client.clone(),
            bucket: bucket.into(),
            key: key.into(),
            expires_in: Duration::from_secs(900),
            query_params: Vec::new(),
            headers: HeaderMap::new(),
        }
    }
}

pub struct BlockingGetObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    range: Option<String>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
    if_unmodified_since: Option<String>,
}

impl BlockingGetObjectRequest {
    pub fn range_bytes(mut self, start: u64, end_inclusive: u64) -> Self {
        self.range = Some(format!("bytes={start}-{end_inclusive}"));
        self
    }

    pub fn if_match(mut self, value: impl Into<String>) -> Self {
        self.if_match = Some(value.into());
        self
    }

    pub fn if_none_match(mut self, value: impl Into<String>) -> Self {
        self.if_none_match = Some(value.into());
        self
    }

    pub fn if_modified_since(mut self, value: impl Into<String>) -> Self {
        self.if_modified_since = Some(value.into());
        self
    }

    pub fn if_unmodified_since(mut self, value: impl Into<String>) -> Self {
        self.if_unmodified_since = Some(value.into());
        self
    }

    pub fn send(self) -> Result<BlockingGetObjectOutput> {
        let mut headers = HeaderMap::new();
        if let Some(range) = self.range {
            let value = HeaderValue::from_str(&range)
                .map_err(|_| Error::invalid_config("invalid Range header"))?;
            headers.insert(http::header::RANGE, value);
        }
        if let Some(value) = self.if_match {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid If-Match header"))?;
            headers.insert(http::header::IF_MATCH, value);
        }
        if let Some(value) = self.if_none_match {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid If-None-Match header"))?;
            headers.insert(http::header::IF_NONE_MATCH, value);
        }
        if let Some(value) = self.if_modified_since {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid If-Modified-Since header"))?;
            headers.insert(http::header::IF_MODIFIED_SINCE, value);
        }
        if let Some(value) = self.if_unmodified_since {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid If-Unmodified-Since header"))?;
            headers.insert(http::header::IF_UNMODIFIED_SINCE, value);
        }

        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            Some(&self.key),
            Vec::new(),
            headers,
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let etag = crate::util::headers::header_string(resp.headers(), http::header::ETAG);
        let content_length =
            crate::util::headers::header_u64(resp.headers(), http::header::CONTENT_LENGTH);
        let content_type =
            crate::util::headers::header_string(resp.headers(), http::header::CONTENT_TYPE);

        Ok(BlockingGetObjectOutput {
            body: BlockingByteStream::new(resp.into_body().into_reader()),
            etag,
            content_length,
            content_type,
        })
    }
}

pub struct BlockingHeadObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
}

impl BlockingHeadObjectRequest {
    pub fn send(self) -> Result<HeadObjectOutput> {
        let resp = self.client.execute(
            Method::HEAD,
            Some(&self.bucket),
            Some(&self.key),
            Vec::new(),
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        Ok(HeadObjectOutput {
            etag: crate::util::headers::header_string(resp.headers(), http::header::ETAG),
            content_length: crate::util::headers::header_u64(
                resp.headers(),
                http::header::CONTENT_LENGTH,
            ),
            content_type: crate::util::headers::header_string(
                resp.headers(),
                http::header::CONTENT_TYPE,
            ),
        })
    }
}

pub struct BlockingPutObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    content_type: Option<String>,
    cache_control: Option<String>,
    content_disposition: Option<String>,
    content_encoding: Option<String>,
    content_language: Option<String>,
    expires: Option<String>,
    #[cfg(feature = "checksums")]
    checksum: Option<crate::types::Checksum>,
    metadata: Vec<(String, String)>,
    body: BlockingBody,
}

impl BlockingPutObjectRequest {
    pub fn content_type(mut self, value: impl Into<String>) -> Self {
        self.content_type = Some(value.into());
        self
    }

    pub fn cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
        self
    }

    pub fn content_disposition(mut self, value: impl Into<String>) -> Self {
        self.content_disposition = Some(value.into());
        self
    }

    pub fn content_encoding(mut self, value: impl Into<String>) -> Self {
        self.content_encoding = Some(value.into());
        self
    }

    pub fn content_language(mut self, value: impl Into<String>) -> Self {
        self.content_language = Some(value.into());
        self
    }

    pub fn expires(mut self, value: impl Into<String>) -> Self {
        self.expires = Some(value.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    #[cfg(feature = "checksums")]
    pub fn checksum(mut self, checksum: crate::types::Checksum) -> Self {
        self.checksum = Some(checksum);
        self
    }

    pub fn body_bytes(mut self, body: impl Into<Bytes>) -> Self {
        self.body = BlockingBody::Bytes(body.into());
        self
    }

    pub fn send(self) -> Result<PutObjectOutput> {
        let mut headers = HeaderMap::new();
        if let Some(ct) = self.content_type {
            let value = HeaderValue::from_str(&ct)
                .map_err(|_| Error::invalid_config("invalid Content-Type header"))?;
            headers.insert(http::header::CONTENT_TYPE, value);
        }
        if let Some(value) = self.cache_control {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Cache-Control header"))?;
            headers.insert(http::header::CACHE_CONTROL, value);
        }
        if let Some(value) = self.content_disposition {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Content-Disposition header"))?;
            headers.insert(http::header::CONTENT_DISPOSITION, value);
        }
        if let Some(value) = self.content_encoding {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Content-Encoding header"))?;
            headers.insert(http::header::CONTENT_ENCODING, value);
        }
        if let Some(value) = self.content_language {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Content-Language header"))?;
            headers.insert(http::header::CONTENT_LANGUAGE, value);
        }
        if let Some(value) = self.expires {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Expires header"))?;
            headers.insert(http::header::EXPIRES, value);
        }

        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        #[cfg(feature = "checksums")]
        if let Some(checksum) = self.checksum {
            checksum.apply(&mut headers)?;
        }

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            Some(&self.key),
            Vec::new(),
            headers,
            self.body,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        Ok(PutObjectOutput {
            etag: crate::util::headers::header_string(resp.headers(), http::header::ETAG),
        })
    }
}

pub struct BlockingDeleteObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
}

impl BlockingDeleteObjectRequest {
    pub fn send(self) -> Result<()> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            Some(&self.key),
            Vec::new(),
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        let status = resp.status();
        if status == StatusCode::NO_CONTENT || status.is_success() {
            return Ok(());
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

pub struct BlockingDeleteObjectsRequest {
    client: BlockingClient,
    bucket: String,
    objects: Vec<DeleteObjectIdentifier>,
    quiet: bool,
}

impl BlockingDeleteObjectsRequest {
    pub fn object(mut self, key: impl Into<String>) -> Self {
        self.objects.push(DeleteObjectIdentifier::new(key));
        self
    }

    pub fn object_with_version(
        mut self,
        key: impl Into<String>,
        version_id: impl Into<String>,
    ) -> Self {
        self.objects
            .push(DeleteObjectIdentifier::new(key).with_version_id(version_id));
        self
    }

    pub fn objects<I, S>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.objects
            .extend(iter.into_iter().map(DeleteObjectIdentifier::new));
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    pub fn send(self) -> Result<DeleteObjectsOutput> {
        let body = crate::util::xml::encode_delete_objects(&self.objects, self.quiet)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );
        let content_md5 = crate::util::md5::content_md5_header_value(body.as_ref())?;
        headers.insert(
            http::header::HeaderName::from_static("content-md5"),
            content_md5,
        );

        let resp = self.client.execute(
            Method::POST,
            Some(&self.bucket),
            None,
            vec![("delete".to_string(), String::new())],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_delete_objects(&xml)
    }
}

pub struct BlockingCopyObjectRequest {
    client: BlockingClient,
    source_bucket: String,
    source_key: String,
    source_version_id: Option<String>,
    destination_bucket: String,
    destination_key: String,
    metadata_directive: Option<MetadataDirective>,
    metadata: Vec<(String, String)>,
    content_type: Option<String>,
}

impl BlockingCopyObjectRequest {
    pub fn source_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.source_version_id = Some(version_id.into());
        self
    }

    pub fn replace_metadata(mut self) -> Self {
        self.metadata_directive = Some(MetadataDirective::Replace);
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    pub fn content_type(mut self, value: impl Into<String>) -> Self {
        self.content_type = Some(value.into());
        self
    }

    pub fn send(self) -> Result<CopyObjectOutput> {
        let mut headers = HeaderMap::new();

        let copy_source = crate::util::headers::copy_source_header_value(
            &self.source_bucket,
            &self.source_key,
            self.source_version_id.as_deref(),
        );
        let copy_source = HeaderValue::from_str(&copy_source)
            .map_err(|_| Error::invalid_config("invalid x-amz-copy-source header"))?;
        headers.insert("x-amz-copy-source", copy_source);

        if matches!(self.metadata_directive, Some(MetadataDirective::Replace)) {
            headers.insert(
                "x-amz-metadata-directive",
                HeaderValue::from_static("REPLACE"),
            );
        }

        if let Some(value) = self.content_type {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Content-Type header"))?;
            headers.insert(http::header::CONTENT_TYPE, value);
        }

        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.destination_bucket),
            Some(&self.destination_key),
            Vec::new(),
            headers,
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_copy_object(&xml)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetadataDirective {
    Replace,
}

#[cfg(feature = "multipart")]
pub struct BlockingCreateMultipartUploadRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    content_type: Option<String>,
    metadata: Vec<(String, String)>,
}

#[cfg(feature = "multipart")]
impl BlockingCreateMultipartUploadRequest {
    pub fn content_type(mut self, value: impl Into<String>) -> Self {
        self.content_type = Some(value.into());
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    pub fn send(self) -> Result<CreateMultipartUploadOutput> {
        let mut headers = HeaderMap::new();
        if let Some(value) = self.content_type {
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid Content-Type header"))?;
            headers.insert(http::header::CONTENT_TYPE, value);
        }

        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        let resp = self.client.execute(
            Method::POST,
            Some(&self.bucket),
            Some(&self.key),
            vec![("uploads".to_string(), String::new())],
            headers,
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_create_multipart_upload(&xml)
    }
}

#[cfg(feature = "multipart")]
pub struct BlockingUploadPartRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    body: BlockingBody,
}

#[cfg(feature = "multipart")]
impl BlockingUploadPartRequest {
    pub fn body_bytes(mut self, body: impl Into<Bytes>) -> Self {
        self.body = BlockingBody::Bytes(body.into());
        self
    }

    pub fn send(self) -> Result<UploadPartOutput> {
        match &self.body {
            BlockingBody::Bytes(_) => {}
            BlockingBody::Empty => {
                return Err(Error::invalid_config("upload_part requires a request body"));
            }
        }

        let query = vec![
            ("partNumber".to_string(), self.part_number.to_string()),
            ("uploadId".to_string(), self.upload_id),
        ];

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.bucket),
            Some(&self.key),
            query,
            HeaderMap::new(),
            self.body,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        Ok(UploadPartOutput {
            etag: crate::util::headers::header_string(resp.headers(), http::header::ETAG),
        })
    }
}

#[cfg(feature = "multipart")]
pub struct BlockingUploadPartCopyRequest {
    client: BlockingClient,
    source_bucket: String,
    source_key: String,
    source_version_id: Option<String>,
    destination_bucket: String,
    destination_key: String,
    upload_id: String,
    part_number: u32,
    copy_source_range: Option<String>,
}

#[cfg(feature = "multipart")]
impl BlockingUploadPartCopyRequest {
    pub fn source_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.source_version_id = Some(version_id.into());
        self
    }

    pub fn copy_source_range_bytes(mut self, start: u64, end_inclusive: u64) -> Self {
        self.copy_source_range = Some(format!("bytes={start}-{end_inclusive}"));
        self
    }

    pub fn send(self) -> Result<UploadPartCopyOutput> {
        let mut headers = HeaderMap::new();

        let copy_source = crate::util::headers::copy_source_header_value(
            &self.source_bucket,
            &self.source_key,
            self.source_version_id.as_deref(),
        );
        let copy_source = HeaderValue::from_str(&copy_source)
            .map_err(|_| Error::invalid_config("invalid x-amz-copy-source header"))?;
        headers.insert("x-amz-copy-source", copy_source);

        if let Some(range) = self.copy_source_range {
            let value = HeaderValue::from_str(&range)
                .map_err(|_| Error::invalid_config("invalid x-amz-copy-source-range header"))?;
            headers.insert("x-amz-copy-source-range", value);
        }

        let query = vec![
            ("partNumber".to_string(), self.part_number.to_string()),
            ("uploadId".to_string(), self.upload_id),
        ];

        let resp = self.client.execute(
            Method::PUT,
            Some(&self.destination_bucket),
            Some(&self.destination_key),
            query,
            headers,
            BlockingBody::Empty,
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_upload_part_copy(&xml)
    }
}

#[cfg(feature = "multipart")]
pub struct BlockingCompleteMultipartUploadRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    upload_id: String,
    parts: Vec<CompletedPart>,
}

#[cfg(feature = "multipart")]
impl BlockingCompleteMultipartUploadRequest {
    pub fn part(mut self, part_number: u32, etag: impl Into<String>) -> Self {
        self.parts.push(CompletedPart {
            part_number,
            etag: etag.into(),
        });
        self
    }

    pub fn parts<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = CompletedPart>,
    {
        self.parts.extend(iter);
        self
    }

    pub fn send(self) -> Result<CompleteMultipartUploadOutput> {
        let body = crate::util::xml::encode_complete_multipart_upload(&self.parts)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml"),
        );

        let resp = self.client.execute(
            Method::POST,
            Some(&self.bucket),
            Some(&self.key),
            vec![("uploadId".to_string(), self.upload_id)],
            headers,
            BlockingBody::Bytes(body),
        )?;

        if !resp.status().is_success() {
            let (parts, body) = resp.into_parts();
            let body = read_body_string(body)?;
            return Err(response_error(parts.status, &parts.headers, &body));
        }

        let (_, body) = resp.into_parts();
        let xml = read_body_string(body)?;
        crate::util::xml::parse_complete_multipart_upload(&xml)
    }
}

#[cfg(feature = "multipart")]
pub struct BlockingAbortMultipartUploadRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    upload_id: String,
}

#[cfg(feature = "multipart")]
impl BlockingAbortMultipartUploadRequest {
    pub fn send(self) -> Result<AbortMultipartUploadOutput> {
        let resp = self.client.execute(
            Method::DELETE,
            Some(&self.bucket),
            Some(&self.key),
            vec![("uploadId".to_string(), self.upload_id)],
            HeaderMap::new(),
            BlockingBody::Empty,
        )?;

        if resp.status() == StatusCode::NO_CONTENT || resp.status().is_success() {
            return Ok(AbortMultipartUploadOutput);
        }

        let (parts, body) = resp.into_parts();
        let body = read_body_string(body)?;
        Err(response_error(parts.status, &parts.headers, &body))
    }
}

#[cfg(feature = "multipart")]
pub struct BlockingListPartsRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    upload_id: String,
    max_parts: Option<u32>,
    part_number_marker: Option<u32>,
}

#[cfg(feature = "multipart")]
impl BlockingListPartsRequest {
    pub fn max_parts(mut self, value: u32) -> Self {
        self.max_parts = Some(value);
        self
    }

    pub fn part_number_marker(mut self, value: u32) -> Self {
        self.part_number_marker = Some(value);
        self
    }

    pub fn send(self) -> Result<ListPartsOutput> {
        let mut query = vec![("uploadId".to_string(), self.upload_id)];
        if let Some(v) = self.max_parts {
            query.push(("max-parts".to_string(), v.to_string()));
        }
        if let Some(v) = self.part_number_marker {
            query.push(("part-number-marker".to_string(), v.to_string()));
        }

        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            Some(&self.key),
            query,
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
        crate::util::xml::parse_list_parts(&xml)
    }
}

pub struct BlockingListObjectsV2Request {
    client: BlockingClient,
    bucket: String,
    prefix: Option<String>,
    delimiter: Option<String>,
    continuation_token: Option<String>,
    start_after: Option<String>,
    max_keys: Option<u32>,
}

impl BlockingListObjectsV2Request {
    pub fn prefix(mut self, value: impl Into<String>) -> Self {
        self.prefix = Some(value.into());
        self
    }

    pub fn delimiter(mut self, value: impl Into<String>) -> Self {
        self.delimiter = Some(value.into());
        self
    }

    pub fn continuation_token(mut self, value: impl Into<String>) -> Self {
        self.continuation_token = Some(value.into());
        self
    }

    pub fn start_after(mut self, value: impl Into<String>) -> Self {
        self.start_after = Some(value.into());
        self
    }

    pub fn max_keys(mut self, value: u32) -> Self {
        self.max_keys = Some(value);
        self
    }

    pub fn pager(self) -> BlockingListObjectsV2Pager {
        BlockingListObjectsV2Pager {
            client: self.client,
            bucket: self.bucket,
            prefix: self.prefix,
            delimiter: self.delimiter,
            continuation_token: self.continuation_token,
            start_after: self.start_after,
            max_keys: self.max_keys,
            done: false,
        }
    }

    pub fn send(self) -> Result<ListObjectsV2Output> {
        let mut query = Vec::new();
        query.push(("list-type".to_string(), "2".to_string()));
        if let Some(v) = self.prefix {
            query.push(("prefix".to_string(), v));
        }
        if let Some(v) = self.delimiter {
            query.push(("delimiter".to_string(), v));
        }
        if let Some(v) = self.continuation_token {
            query.push(("continuation-token".to_string(), v));
        }
        if let Some(v) = self.start_after {
            query.push(("start-after".to_string(), v));
        }
        if let Some(v) = self.max_keys {
            query.push(("max-keys".to_string(), v.to_string()));
        }

        let resp = self.client.execute(
            Method::GET,
            Some(&self.bucket),
            None,
            query,
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
        crate::util::xml::parse_list_objects_v2(&xml)
    }
}

pub struct BlockingListObjectsV2Pager {
    client: BlockingClient,
    bucket: String,
    prefix: Option<String>,
    delimiter: Option<String>,
    continuation_token: Option<String>,
    start_after: Option<String>,
    max_keys: Option<u32>,
    done: bool,
}

impl Iterator for BlockingListObjectsV2Pager {
    type Item = Result<ListObjectsV2Output>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let start_after = if self.continuation_token.is_some() {
            None
        } else {
            self.start_after.clone()
        };

        let page = BlockingListObjectsV2Request {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            delimiter: self.delimiter.clone(),
            continuation_token: self.continuation_token.clone(),
            start_after,
            max_keys: self.max_keys,
        }
        .send();

        match page {
            Ok(page) => {
                self.continuation_token = page.next_continuation_token.clone();
                if !page.is_truncated {
                    self.done = true;
                }
                Some(Ok(page))
            }
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }
}

pub struct BlockingPresignObjectRequest {
    client: BlockingClient,
    method: Method,
    bucket: String,
    key: String,
    expires_in: Duration,
    query_params: Vec<(String, String)>,
    headers: HeaderMap,
    metadata: Vec<(String, String)>,
}

impl BlockingPresignObjectRequest {
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((name.into(), value.into()));
        self
    }

    pub fn header(mut self, name: http::header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> Result<PresignedRequest> {
        let mut headers = self.headers;
        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        self.client.presign(
            self.method,
            &self.bucket,
            &self.key,
            self.expires_in,
            self.query_params,
            headers,
        )
    }
}

pub struct BlockingPresignGetObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    expires_in: Duration,
    query_params: Vec<(String, String)>,
    headers: HeaderMap,
    metadata: Vec<(String, String)>,
}

impl BlockingPresignGetObjectRequest {
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((name.into(), value.into()));
        self
    }

    pub fn header(mut self, name: http::header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> Result<PresignedRequest> {
        let mut headers = self.headers;
        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        self.client.presign(
            Method::GET,
            &self.bucket,
            &self.key,
            self.expires_in,
            self.query_params,
            headers,
        )
    }
}

pub struct BlockingPresignPutObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    expires_in: Duration,
    query_params: Vec<(String, String)>,
    headers: HeaderMap,
    metadata: Vec<(String, String)>,
}

impl BlockingPresignPutObjectRequest {
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((name.into(), value.into()));
        self
    }

    pub fn header(mut self, name: http::header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> Result<PresignedRequest> {
        let mut headers = self.headers;
        for (name, value) in self.metadata {
            let header_name = crate::util::redact::metadata_header_name(&name)?;
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::invalid_config("invalid metadata header value"))?;
            headers.insert(header_name, value);
        }

        self.client.presign(
            Method::PUT,
            &self.bucket,
            &self.key,
            self.expires_in,
            self.query_params,
            headers,
        )
    }
}

pub struct BlockingPresignHeadObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    expires_in: Duration,
    query_params: Vec<(String, String)>,
    headers: HeaderMap,
}

impl BlockingPresignHeadObjectRequest {
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((name.into(), value.into()));
        self
    }

    pub fn header(mut self, name: http::header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn build(self) -> Result<PresignedRequest> {
        self.client.presign(
            Method::HEAD,
            &self.bucket,
            &self.key,
            self.expires_in,
            self.query_params,
            self.headers,
        )
    }
}

pub struct BlockingPresignDeleteObjectRequest {
    client: BlockingClient,
    bucket: String,
    key: String,
    expires_in: Duration,
    query_params: Vec<(String, String)>,
    headers: HeaderMap,
}

impl BlockingPresignDeleteObjectRequest {
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((name.into(), value.into()));
        self
    }

    pub fn header(mut self, name: http::header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn build(self) -> Result<PresignedRequest> {
        self.client.presign(
            Method::DELETE,
            &self.bucket,
            &self.key,
            self.expires_in,
            self.query_params,
            self.headers,
        )
    }
}
