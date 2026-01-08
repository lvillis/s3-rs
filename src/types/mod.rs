//! Shared request and response types.

use bytes::Bytes;
use http::{HeaderMap, Method};
use serde::Deserialize;
use url::Url;

use crate::error::{Error, Result};

#[cfg(feature = "async")]
/// Streaming response body for async operations.
pub type ByteStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Bytes>> + Send + 'static>>;

/// Fully resolved presigned request.
#[derive(Clone, Debug)]
pub struct PresignedRequest {
    /// HTTP method to use.
    pub method: Method,
    /// Fully signed request URL.
    pub url: Url,
    /// Headers that must accompany the request.
    pub headers: HeaderMap,
}

#[cfg(feature = "async")]
/// Output from a GET object request.
pub struct GetObjectOutput {
    /// Response body stream.
    pub body: ByteStream,
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Content length, if known.
    pub content_length: Option<u64>,
    /// Content type, if provided.
    pub content_type: Option<String>,
}

#[cfg(feature = "blocking")]
/// Blocking response body reader.
pub struct BlockingByteStream {
    inner: Box<dyn std::io::Read + 'static>,
}

#[cfg(feature = "blocking")]
impl BlockingByteStream {
    pub(crate) fn new<R>(reader: R) -> Self
    where
        R: std::io::Read + 'static,
    {
        Self {
            inner: Box::new(reader),
        }
    }
}

#[cfg(feature = "blocking")]
impl std::fmt::Debug for BlockingByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingByteStream")
            .field("inner", &"<reader>")
            .finish()
    }
}

#[cfg(feature = "blocking")]
impl std::io::Read for BlockingByteStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(feature = "blocking")]
/// Output from a blocking GET object request.
#[derive(Debug)]
pub struct BlockingGetObjectOutput {
    /// Response body reader.
    pub body: BlockingByteStream,
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Content length, if known.
    pub content_length: Option<u64>,
    /// Content type, if provided.
    pub content_type: Option<String>,
}

#[cfg(feature = "blocking")]
impl BlockingGetObjectOutput {
    /// Reads the full response body into memory.
    pub fn bytes(mut self) -> Result<Bytes> {
        use std::io::Read as _;

        let mut out = Vec::new();
        self.body
            .read_to_end(&mut out)
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        Ok(Bytes::from(out))
    }

    /// Streams the response body into the provided writer.
    pub fn write_to<W>(mut self, writer: &mut W) -> Result<u64>
    where
        W: std::io::Write,
    {
        let bytes_copied = std::io::copy(&mut self.body, writer)
            .map_err(|e| Error::transport("failed to write response body", Some(Box::new(e))))?;
        Ok(bytes_copied)
    }
}

#[cfg(feature = "async")]
impl std::fmt::Debug for GetObjectOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetObjectOutput")
            .field("body", &"<stream>")
            .field("etag", &self.etag)
            .field("content_length", &self.content_length)
            .field("content_type", &self.content_type)
            .finish()
    }
}

#[cfg(feature = "async")]
impl GetObjectOutput {
    /// Collects the response body into memory.
    pub async fn bytes(self) -> Result<Bytes> {
        use futures_util::StreamExt as _;

        let mut out = Vec::new();
        let mut stream = self.body;
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(out))
    }

    /// Streams the response body into the provided writer.
    pub async fn write_to<W>(self, writer: &mut W) -> Result<u64>
    where
        W: futures_io::AsyncWrite + Unpin,
    {
        use futures_util::{StreamExt as _, io::AsyncWriteExt as _};

        let mut written = 0u64;
        let mut stream = self.body;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await.map_err(|e| {
                Error::transport("failed to write response body", Some(Box::new(e)))
            })?;
            written = written.saturating_add(chunk.len() as u64);
        }

        writer
            .flush()
            .await
            .map_err(|e| Error::transport("failed to flush writer", Some(Box::new(e))))?;

        Ok(written)
    }
}

/// Output from a HEAD object request.
#[derive(Debug)]
pub struct HeadObjectOutput {
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Content length, if known.
    pub content_length: Option<u64>,
    /// Content type, if provided.
    pub content_type: Option<String>,
}

/// Output from a PUT object request.
#[derive(Debug)]
pub struct PutObjectOutput {
    /// Entity tag, if provided.
    pub etag: Option<String>,
}

#[cfg(feature = "checksums")]
/// Supported checksum algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    /// CRC32 (ISO HDLC).
    Crc32,
    /// CRC32C (Castagnoli).
    Crc32c,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
}

#[cfg(feature = "checksums")]
impl ChecksumAlgorithm {
    /// Returns the checksum header name for this algorithm.
    pub fn header_name(self) -> http::header::HeaderName {
        match self {
            Self::Crc32 => http::header::HeaderName::from_static("x-amz-checksum-crc32"),
            Self::Crc32c => http::header::HeaderName::from_static("x-amz-checksum-crc32c"),
            Self::Sha1 => http::header::HeaderName::from_static("x-amz-checksum-sha1"),
            Self::Sha256 => http::header::HeaderName::from_static("x-amz-checksum-sha256"),
        }
    }
}

#[cfg(feature = "checksums")]
/// Checksum value to send with a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    /// Checksum algorithm.
    pub algorithm: ChecksumAlgorithm,
    /// Base64-encoded checksum value.
    pub value: String,
}

#[cfg(feature = "checksums")]
impl Checksum {
    /// Creates a checksum with a pre-encoded value.
    pub fn new(algorithm: ChecksumAlgorithm, value: impl Into<String>) -> Self {
        Self {
            algorithm,
            value: value.into(),
        }
    }

    /// Computes a checksum from raw bytes.
    pub fn from_bytes(algorithm: ChecksumAlgorithm, bytes: impl AsRef<[u8]>) -> Self {
        use base64::Engine as _;

        let bytes = bytes.as_ref();
        let value = match algorithm {
            ChecksumAlgorithm::Crc32 => {
                const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
                let checksum = CRC32.checksum(bytes).to_be_bytes();
                base64::engine::general_purpose::STANDARD.encode(checksum)
            }
            ChecksumAlgorithm::Crc32c => {
                const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
                let checksum = CRC32C.checksum(bytes).to_be_bytes();
                base64::engine::general_purpose::STANDARD.encode(checksum)
            }
            ChecksumAlgorithm::Sha1 => {
                use sha1::Digest as _;

                let digest = sha1::Sha1::digest(bytes);
                base64::engine::general_purpose::STANDARD.encode(digest)
            }
            ChecksumAlgorithm::Sha256 => {
                use sha2::Digest as _;

                let digest = sha2::Sha256::digest(bytes);
                base64::engine::general_purpose::STANDARD.encode(digest)
            }
        };

        Self { algorithm, value }
    }

    pub(crate) fn apply(&self, headers: &mut HeaderMap) -> Result<()> {
        let value = http::HeaderValue::from_str(&self.value)
            .map_err(|_| Error::invalid_config("invalid checksum header value"))?;
        headers.insert(self.algorithm.header_name(), value);
        Ok(())
    }
}

/// Output from a DELETE object request.
#[derive(Debug)]
pub struct DeleteObjectOutput;

/// Output from a multi-delete request.
#[derive(Debug)]
pub struct DeleteObjectsOutput {
    /// Successfully deleted objects.
    pub deleted: Vec<DeletedObject>,
    /// Per-object errors.
    pub errors: Vec<DeleteObjectError>,
}

/// Identifier for an object in delete requests.
#[derive(Clone, Debug)]
pub struct DeleteObjectIdentifier {
    /// Object key.
    pub key: String,
    /// Optional version id.
    pub version_id: Option<String>,
}

impl DeleteObjectIdentifier {
    /// Creates an identifier from an object key.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            version_id: None,
        }
    }

    /// Sets the version id for this identifier.
    pub fn with_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }
}

/// Successfully deleted object metadata.
#[derive(Debug)]
pub struct DeletedObject {
    /// Object key, if reported.
    pub key: Option<String>,
    /// Version id, if reported.
    pub version_id: Option<String>,
    /// Whether a delete marker was created.
    pub delete_marker: Option<bool>,
    /// Delete marker version id, if reported.
    pub delete_marker_version_id: Option<String>,
}

/// Error metadata for a failed delete entry.
#[derive(Debug)]
pub struct DeleteObjectError {
    /// Object key, if reported.
    pub key: Option<String>,
    /// Version id, if reported.
    pub version_id: Option<String>,
    /// Error code, if reported.
    pub code: Option<String>,
    /// Error message, if reported.
    pub message: Option<String>,
}

/// Output from a copy object request.
#[derive(Debug)]
pub struct CopyObjectOutput {
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Last-modified timestamp, if provided.
    pub last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
/// Output from initiating a multipart upload.
#[derive(Debug)]
pub struct CreateMultipartUploadOutput {
    /// Bucket name, if provided.
    pub bucket: Option<String>,
    /// Object key, if provided.
    pub key: Option<String>,
    /// Upload id to use for subsequent part uploads.
    pub upload_id: String,
}

#[cfg(feature = "multipart")]
/// Output from uploading a multipart part.
#[derive(Debug)]
pub struct UploadPartOutput {
    /// Entity tag for the uploaded part.
    pub etag: Option<String>,
}

#[cfg(feature = "multipart")]
/// Completed part descriptor for multipart completion.
#[derive(Clone, Debug)]
pub struct CompletedPart {
    /// Part number.
    pub part_number: u32,
    /// Part etag.
    pub etag: String,
}

#[cfg(feature = "multipart")]
/// Output from completing a multipart upload.
#[derive(Debug)]
pub struct CompleteMultipartUploadOutput {
    /// Object location, if provided.
    pub location: Option<String>,
    /// Bucket name, if provided.
    pub bucket: Option<String>,
    /// Object key, if provided.
    pub key: Option<String>,
    /// Entity tag, if provided.
    pub etag: Option<String>,
}

#[cfg(feature = "multipart")]
/// Output from aborting a multipart upload.
#[derive(Debug)]
pub struct AbortMultipartUploadOutput;

#[cfg(feature = "multipart")]
/// Output from listing multipart parts.
#[derive(Debug)]
pub struct ListPartsOutput {
    /// Bucket name, if provided.
    pub bucket: Option<String>,
    /// Object key, if provided.
    pub key: Option<String>,
    /// Upload id, if provided.
    pub upload_id: Option<String>,
    /// Whether the listing is truncated.
    pub is_truncated: bool,
    /// Marker for the current page.
    pub part_number_marker: Option<u32>,
    /// Marker for the next page.
    pub next_part_number_marker: Option<u32>,
    /// Maximum number of parts requested.
    pub max_parts: Option<u32>,
    /// Listed parts.
    pub parts: Vec<Part>,
}

#[cfg(feature = "multipart")]
/// Metadata for a multipart part.
#[derive(Debug)]
pub struct Part {
    /// Part number.
    pub part_number: u32,
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// Last-modified timestamp, if provided.
    pub last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
/// Output from copying a multipart part.
#[derive(Debug)]
pub struct UploadPartCopyOutput {
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Last-modified timestamp, if provided.
    pub last_modified: Option<String>,
}

/// Output from a ListObjectsV2 request.
#[derive(Debug)]
pub struct ListObjectsV2Output {
    /// Bucket name.
    pub name: String,
    /// Prefix filter, if any.
    pub prefix: Option<String>,
    /// Delimiter used for grouping, if any.
    pub delimiter: Option<String>,
    /// Whether the listing is truncated.
    pub is_truncated: bool,
    /// Number of keys returned, if reported.
    pub key_count: Option<u32>,
    /// Maximum number of keys requested.
    pub max_keys: Option<u32>,
    /// Continuation token used for this response, if any.
    pub continuation_token: Option<String>,
    /// Continuation token for the next page, if any.
    pub next_continuation_token: Option<String>,
    /// Listed objects.
    pub contents: Vec<Object>,
    /// Common prefixes when using delimiters.
    pub common_prefixes: Vec<String>,
}

/// Object metadata returned by list operations.
#[derive(Debug)]
pub struct Object {
    /// Object key.
    pub key: String,
    /// Object size in bytes.
    pub size: u64,
    /// Entity tag, if provided.
    pub etag: Option<String>,
    /// Last-modified timestamp, if provided.
    pub last_modified: Option<String>,
    /// Storage class, if provided.
    pub storage_class: Option<String>,
}

/// Output from listing buckets.
#[derive(Debug)]
pub struct ListBucketsOutput {
    /// Owner information, if provided.
    pub owner: Option<BucketOwner>,
    /// Buckets returned in the response.
    pub buckets: Vec<Bucket>,
}

/// Bucket owner metadata.
#[derive(Debug)]
pub struct BucketOwner {
    /// Owner id, if provided.
    pub id: Option<String>,
    /// Owner display name, if provided.
    pub display_name: Option<String>,
}

/// Bucket listing entry.
#[derive(Debug)]
pub struct Bucket {
    /// Bucket name.
    pub name: String,
    /// Creation date, if provided.
    pub creation_date: Option<String>,
}

/// Output from a HEAD bucket request.
#[derive(Debug)]
pub struct HeadBucketOutput {
    /// Bucket region, if provided.
    pub region: Option<String>,
}

/// Output from a create bucket request.
#[derive(Debug)]
pub struct CreateBucketOutput;

/// Output from a delete bucket request.
#[derive(Debug)]
pub struct DeleteBucketOutput;

/// Bucket versioning configuration.
#[derive(Clone, Debug, Default)]
pub struct BucketVersioningConfiguration {
    /// Versioning status.
    pub status: Option<BucketVersioningStatus>,
    /// MFA delete status.
    pub mfa_delete: Option<BucketMfaDeleteStatus>,
}

/// Versioning status values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketVersioningStatus {
    /// Enable versioning.
    Enabled,
    /// Suspend versioning.
    Suspended,
}

/// MFA delete status values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketMfaDeleteStatus {
    /// Enable MFA delete.
    Enabled,
    /// Disable MFA delete.
    Disabled,
}

/// Output from updating bucket versioning.
#[derive(Debug)]
pub struct PutBucketVersioningOutput;

/// Bucket lifecycle configuration.
#[derive(Clone, Debug, Default)]
pub struct BucketLifecycleConfiguration {
    /// Lifecycle rules.
    pub rules: Vec<BucketLifecycleRule>,
}

/// Lifecycle rule definition.
#[derive(Clone, Debug)]
pub struct BucketLifecycleRule {
    /// Optional rule id.
    pub id: Option<String>,
    /// Rule status.
    pub status: BucketLifecycleStatus,
    /// Prefix filter.
    pub prefix: Option<String>,
    /// Expiration in days.
    pub expiration_days: Option<u32>,
    /// Expiration date (ISO 8601), if provided.
    pub expiration_date: Option<String>,
}

/// Lifecycle rule status values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BucketLifecycleStatus {
    /// Enable the rule.
    #[default]
    Enabled,
    /// Disable the rule.
    Disabled,
}

/// Output from updating bucket lifecycle configuration.
#[derive(Debug)]
pub struct PutBucketLifecycleOutput;

/// Output from deleting bucket lifecycle configuration.
#[derive(Debug)]
pub struct DeleteBucketLifecycleOutput;

/// Bucket CORS configuration.
#[derive(Clone, Debug, Default)]
pub struct BucketCorsConfiguration {
    /// CORS rules.
    pub rules: Vec<BucketCorsRule>,
}

/// Bucket CORS rule definition.
#[derive(Clone, Debug)]
pub struct BucketCorsRule {
    /// Optional rule id.
    pub id: Option<String>,
    /// Allowed origins.
    pub allowed_origins: Vec<String>,
    /// Allowed methods.
    pub allowed_methods: Vec<CorsMethod>,
    /// Allowed headers.
    pub allowed_headers: Vec<String>,
    /// Exposed headers.
    pub expose_headers: Vec<String>,
    /// Max age in seconds.
    pub max_age_seconds: Option<u32>,
}

/// Allowed CORS method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsMethod {
    /// HTTP GET.
    Get,
    /// HTTP PUT.
    Put,
    /// HTTP POST.
    Post,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// Custom method.
    Other(String),
}

impl CorsMethod {
    /// Returns the wire value for this method.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Other(v) => v.as_str(),
        }
    }
}

/// Output from updating bucket CORS configuration.
#[derive(Debug)]
pub struct PutBucketCorsOutput;

/// Output from deleting bucket CORS configuration.
#[derive(Debug)]
pub struct DeleteBucketCorsOutput;

/// Bucket tag set.
#[derive(Clone, Debug, Default)]
pub struct BucketTagging {
    /// Tags associated with the bucket.
    pub tags: Vec<Tag>,
}

/// Tag key/value pair.
#[derive(Clone, Debug)]
pub struct Tag {
    /// Tag key.
    pub key: String,
    /// Tag value.
    pub value: String,
}

/// Output from updating bucket tags.
#[derive(Debug)]
pub struct PutBucketTaggingOutput;

/// Output from deleting bucket tags.
#[derive(Debug)]
pub struct DeleteBucketTaggingOutput;

/// Bucket encryption configuration.
#[derive(Clone, Debug, Default)]
pub struct BucketEncryptionConfiguration {
    /// Encryption rules.
    pub rules: Vec<BucketEncryptionRule>,
}

/// Bucket encryption rule definition.
#[derive(Clone, Debug)]
pub struct BucketEncryptionRule {
    /// Default server-side encryption settings.
    pub apply: ApplyServerSideEncryptionByDefault,
    /// Whether bucket keys are enabled.
    pub bucket_key_enabled: Option<bool>,
}

/// Default server-side encryption settings.
#[derive(Clone, Debug)]
pub struct ApplyServerSideEncryptionByDefault {
    /// Server-side encryption algorithm.
    pub sse_algorithm: SseAlgorithm,
    /// KMS master key id, if applicable.
    pub kms_master_key_id: Option<String>,
}

/// Server-side encryption algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseAlgorithm {
    /// AES-256.
    Aes256,
    /// AWS KMS.
    AwsKms,
    /// AWS KMS with DSSE.
    AwsKmsDsse,
    /// Custom algorithm.
    Other(String),
}

impl SseAlgorithm {
    /// Returns the wire value for this algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Aes256 => "AES256",
            Self::AwsKms => "aws:kms",
            Self::AwsKmsDsse => "aws:kms:dsse",
            Self::Other(v) => v.as_str(),
        }
    }
}

/// Output from updating bucket encryption configuration.
#[derive(Debug)]
pub struct PutBucketEncryptionOutput;

/// Output from deleting bucket encryption configuration.
#[derive(Debug)]
pub struct DeleteBucketEncryptionOutput;

/// Bucket public access block configuration.
#[derive(Clone, Debug, Default)]
pub struct BucketPublicAccessBlockConfiguration {
    /// Block public ACLs.
    pub block_public_acls: bool,
    /// Ignore public ACLs.
    pub ignore_public_acls: bool,
    /// Block public bucket policies.
    pub block_public_policy: bool,
    /// Restrict public buckets.
    pub restrict_public_buckets: bool,
}

/// Output from updating public access block settings.
#[derive(Debug)]
pub struct PutBucketPublicAccessBlockOutput;

/// Output from deleting public access block settings.
#[derive(Debug)]
pub struct DeleteBucketPublicAccessBlockOutput;

#[derive(Debug, Deserialize)]
pub(crate) struct XmlError {
    #[serde(rename = "Code")]
    pub(crate) code: Option<String>,
    #[serde(rename = "Message")]
    pub(crate) message: Option<String>,
    #[serde(rename = "RequestId")]
    pub(crate) request_id: Option<String>,
    #[serde(rename = "HostId")]
    pub(crate) host_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlListBucketResult {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(rename = "Prefix")]
    pub(crate) prefix: Option<String>,
    #[serde(rename = "Delimiter")]
    pub(crate) delimiter: Option<String>,
    #[serde(rename = "IsTruncated")]
    pub(crate) is_truncated: Option<bool>,
    #[serde(rename = "KeyCount")]
    pub(crate) key_count: Option<u32>,
    #[serde(rename = "MaxKeys")]
    pub(crate) max_keys: Option<u32>,
    #[serde(rename = "ContinuationToken")]
    pub(crate) continuation_token: Option<String>,
    #[serde(rename = "NextContinuationToken")]
    pub(crate) next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    pub(crate) contents: Vec<XmlObject>,
    #[serde(rename = "CommonPrefixes", default)]
    pub(crate) common_prefixes: Vec<XmlCommonPrefixes>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlObject {
    #[serde(rename = "Key")]
    pub(crate) key: String,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: Option<String>,
    #[serde(rename = "ETag")]
    pub(crate) etag: Option<String>,
    #[serde(rename = "Size")]
    pub(crate) size: u64,
    #[serde(rename = "StorageClass")]
    pub(crate) storage_class: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlCommonPrefixes {
    #[serde(rename = "Prefix")]
    pub(crate) prefix: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlDeleteResult {
    #[serde(rename = "Deleted", default)]
    pub(crate) deleted: Vec<XmlDeleted>,
    #[serde(rename = "Error", default)]
    pub(crate) errors: Vec<XmlDeleteError>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlDeleted {
    #[serde(rename = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "VersionId")]
    pub(crate) version_id: Option<String>,
    #[serde(rename = "DeleteMarker")]
    pub(crate) delete_marker: Option<bool>,
    #[serde(rename = "DeleteMarkerVersionId")]
    pub(crate) delete_marker_version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlDeleteError {
    #[serde(rename = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "VersionId")]
    pub(crate) version_id: Option<String>,
    #[serde(rename = "Code")]
    pub(crate) code: Option<String>,
    #[serde(rename = "Message")]
    pub(crate) message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlCopyObjectResult {
    #[serde(rename = "ETag")]
    pub(crate) etag: Option<String>,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug, Deserialize)]
pub(crate) struct XmlInitiateMultipartUploadResult {
    #[serde(rename = "Bucket")]
    pub(crate) bucket: Option<String>,
    #[serde(rename = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "UploadId")]
    pub(crate) upload_id: String,
}

#[cfg(feature = "multipart")]
#[derive(Debug, Deserialize)]
pub(crate) struct XmlCompleteMultipartUploadResult {
    #[serde(rename = "Location")]
    pub(crate) location: Option<String>,
    #[serde(rename = "Bucket")]
    pub(crate) bucket: Option<String>,
    #[serde(rename = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "ETag")]
    pub(crate) etag: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug, Deserialize)]
pub(crate) struct XmlListPartsResult {
    #[serde(rename = "Bucket")]
    pub(crate) bucket: Option<String>,
    #[serde(rename = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "UploadId")]
    pub(crate) upload_id: Option<String>,
    #[serde(rename = "IsTruncated")]
    pub(crate) is_truncated: Option<bool>,
    #[serde(rename = "PartNumberMarker")]
    pub(crate) part_number_marker: Option<u32>,
    #[serde(rename = "NextPartNumberMarker")]
    pub(crate) next_part_number_marker: Option<u32>,
    #[serde(rename = "MaxParts")]
    pub(crate) max_parts: Option<u32>,
    #[serde(rename = "Part", default)]
    pub(crate) parts: Vec<XmlPart>,
}

#[cfg(feature = "multipart")]
#[derive(Debug, Deserialize)]
pub(crate) struct XmlPart {
    #[serde(rename = "PartNumber")]
    pub(crate) part_number: u32,
    #[serde(rename = "ETag")]
    pub(crate) etag: Option<String>,
    #[serde(rename = "Size")]
    pub(crate) size: u64,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug, Deserialize)]
pub(crate) struct XmlCopyPartResult {
    #[serde(rename = "ETag")]
    pub(crate) etag: Option<String>,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlListAllMyBucketsResult {
    #[serde(rename = "Owner")]
    pub(crate) owner: Option<XmlOwner>,
    #[serde(rename = "Buckets")]
    pub(crate) buckets: Option<XmlBuckets>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlOwner {
    #[serde(rename = "ID")]
    pub(crate) id: Option<String>,
    #[serde(rename = "DisplayName")]
    pub(crate) display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlBuckets {
    #[serde(rename = "Bucket", default)]
    pub(crate) buckets: Vec<XmlBucket>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlBucket {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(rename = "CreationDate")]
    pub(crate) creation_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlVersioningConfiguration {
    #[serde(rename = "Status")]
    pub(crate) status: Option<String>,
    #[serde(rename = "MfaDelete")]
    pub(crate) mfa_delete: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlLifecycleConfiguration {
    #[serde(rename = "Rule", default)]
    pub(crate) rules: Vec<XmlLifecycleRule>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlLifecycleRule {
    #[serde(rename = "ID")]
    pub(crate) id: Option<String>,
    #[serde(rename = "Status")]
    pub(crate) status: String,
    #[serde(rename = "Prefix")]
    pub(crate) prefix: Option<String>,
    #[serde(rename = "Filter")]
    pub(crate) filter: Option<XmlLifecycleFilter>,
    #[serde(rename = "Expiration")]
    pub(crate) expiration: Option<XmlExpiration>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlLifecycleFilter {
    #[serde(rename = "Prefix")]
    pub(crate) prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlExpiration {
    #[serde(rename = "Days")]
    pub(crate) days: Option<u32>,
    #[serde(rename = "Date")]
    pub(crate) date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlCorsConfiguration {
    #[serde(rename = "CORSRule", default)]
    pub(crate) rules: Vec<XmlCorsRule>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlCorsRule {
    #[serde(rename = "ID")]
    pub(crate) id: Option<String>,
    #[serde(rename = "AllowedOrigin", default)]
    pub(crate) allowed_origins: Vec<String>,
    #[serde(rename = "AllowedMethod", default)]
    pub(crate) allowed_methods: Vec<String>,
    #[serde(rename = "AllowedHeader", default)]
    pub(crate) allowed_headers: Vec<String>,
    #[serde(rename = "ExposeHeader", default)]
    pub(crate) expose_headers: Vec<String>,
    #[serde(rename = "MaxAgeSeconds")]
    pub(crate) max_age_seconds: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlTagging {
    #[serde(rename = "TagSet")]
    pub(crate) tag_set: Option<XmlTagSet>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlTagSet {
    #[serde(rename = "Tag", default)]
    pub(crate) tags: Vec<XmlTag>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlTag {
    #[serde(rename = "Key")]
    pub(crate) key: String,
    #[serde(rename = "Value")]
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlServerSideEncryptionConfiguration {
    #[serde(rename = "Rule", default)]
    pub(crate) rules: Vec<XmlServerSideEncryptionRule>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlServerSideEncryptionRule {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    pub(crate) apply: Option<XmlApplyServerSideEncryptionByDefault>,
    #[serde(rename = "BucketKeyEnabled")]
    pub(crate) bucket_key_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlApplyServerSideEncryptionByDefault {
    #[serde(rename = "SSEAlgorithm")]
    pub(crate) sse_algorithm: String,
    #[serde(rename = "KMSMasterKeyID")]
    pub(crate) kms_master_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct XmlPublicAccessBlockConfiguration {
    #[serde(rename = "BlockPublicAcls")]
    pub(crate) block_public_acls: Option<bool>,
    #[serde(rename = "IgnorePublicAcls")]
    pub(crate) ignore_public_acls: Option<bool>,
    #[serde(rename = "BlockPublicPolicy")]
    pub(crate) block_public_policy: Option<bool>,
    #[serde(rename = "RestrictPublicBuckets")]
    pub(crate) restrict_public_buckets: Option<bool>,
}

impl TryFrom<XmlListBucketResult> for ListObjectsV2Output {
    type Error = Error;

    fn try_from(value: XmlListBucketResult) -> Result<Self> {
        Ok(Self {
            name: value.name,
            prefix: value.prefix,
            delimiter: value.delimiter,
            is_truncated: value.is_truncated.unwrap_or(false),
            key_count: value.key_count,
            max_keys: value.max_keys,
            continuation_token: value.continuation_token,
            next_continuation_token: value.next_continuation_token,
            contents: value
                .contents
                .into_iter()
                .map(|o| Object {
                    key: o.key,
                    size: o.size,
                    etag: o.etag,
                    last_modified: o.last_modified,
                    storage_class: o.storage_class,
                })
                .collect(),
            common_prefixes: value
                .common_prefixes
                .into_iter()
                .map(|p| p.prefix)
                .collect(),
        })
    }
}

impl From<XmlListAllMyBucketsResult> for ListBucketsOutput {
    fn from(value: XmlListAllMyBucketsResult) -> Self {
        let buckets = value
            .buckets
            .map(|b| {
                b.buckets
                    .into_iter()
                    .map(|bucket| Bucket {
                        name: bucket.name,
                        creation_date: bucket.creation_date,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            owner: value.owner.map(|o| BucketOwner {
                id: o.id,
                display_name: o.display_name,
            }),
            buckets,
        }
    }
}

impl From<XmlDeleteResult> for DeleteObjectsOutput {
    fn from(value: XmlDeleteResult) -> Self {
        Self {
            deleted: value
                .deleted
                .into_iter()
                .map(|d| DeletedObject {
                    key: d.key,
                    version_id: d.version_id,
                    delete_marker: d.delete_marker,
                    delete_marker_version_id: d.delete_marker_version_id,
                })
                .collect(),
            errors: value
                .errors
                .into_iter()
                .map(|e| DeleteObjectError {
                    key: e.key,
                    version_id: e.version_id,
                    code: e.code,
                    message: e.message,
                })
                .collect(),
        }
    }
}

impl From<XmlCopyObjectResult> for CopyObjectOutput {
    fn from(value: XmlCopyObjectResult) -> Self {
        Self {
            etag: value.etag,
            last_modified: value.last_modified,
        }
    }
}

#[cfg(all(test, feature = "checksums"))]
mod checksum_tests {
    use super::{Checksum, ChecksumAlgorithm};

    #[test]
    fn from_bytes_matches_known_vectors() {
        let bytes = b"hello";

        assert_eq!(
            Checksum::from_bytes(ChecksumAlgorithm::Sha256, bytes).value,
            "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="
        );
        assert_eq!(
            Checksum::from_bytes(ChecksumAlgorithm::Sha1, bytes).value,
            "qvTGHdzF6KLavt4PO0gs2a6pQ00="
        );
        assert_eq!(
            Checksum::from_bytes(ChecksumAlgorithm::Crc32, bytes).value,
            "NhCmhg=="
        );
        assert_eq!(
            Checksum::from_bytes(ChecksumAlgorithm::Crc32c, bytes).value,
            "mnG7TA=="
        );
    }
}

#[cfg(feature = "multipart")]
impl From<XmlInitiateMultipartUploadResult> for CreateMultipartUploadOutput {
    fn from(value: XmlInitiateMultipartUploadResult) -> Self {
        Self {
            bucket: value.bucket,
            key: value.key,
            upload_id: value.upload_id,
        }
    }
}

#[cfg(feature = "multipart")]
impl From<XmlCompleteMultipartUploadResult> for CompleteMultipartUploadOutput {
    fn from(value: XmlCompleteMultipartUploadResult) -> Self {
        Self {
            location: value.location,
            bucket: value.bucket,
            key: value.key,
            etag: value.etag,
        }
    }
}

#[cfg(feature = "multipart")]
impl From<XmlListPartsResult> for ListPartsOutput {
    fn from(value: XmlListPartsResult) -> Self {
        Self {
            bucket: value.bucket,
            key: value.key,
            upload_id: value.upload_id,
            is_truncated: value.is_truncated.unwrap_or(false),
            part_number_marker: value.part_number_marker,
            next_part_number_marker: value.next_part_number_marker,
            max_parts: value.max_parts,
            parts: value
                .parts
                .into_iter()
                .map(|p| Part {
                    part_number: p.part_number,
                    etag: p.etag,
                    size: p.size,
                    last_modified: p.last_modified,
                })
                .collect(),
        }
    }
}

#[cfg(feature = "multipart")]
impl From<XmlCopyPartResult> for UploadPartCopyOutput {
    fn from(value: XmlCopyPartResult) -> Self {
        Self {
            etag: value.etag,
            last_modified: value.last_modified,
        }
    }
}
