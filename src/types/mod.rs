use bytes::Bytes;
use http::{HeaderMap, Method};
use serde::Deserialize;
use url::Url;

use crate::error::{Error, Result};

#[cfg(feature = "async")]
pub type ByteStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Bytes>> + Send + 'static>>;

#[derive(Clone, Debug)]
pub struct PresignedRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
}

#[cfg(feature = "async")]
pub struct GetObjectOutput {
    pub body: ByteStream,
    pub etag: Option<String>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
}

#[cfg(feature = "blocking")]
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
#[derive(Debug)]
pub struct BlockingGetObjectOutput {
    pub body: BlockingByteStream,
    pub etag: Option<String>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
}

#[cfg(feature = "blocking")]
impl BlockingGetObjectOutput {
    pub fn bytes(mut self) -> Result<Bytes> {
        use std::io::Read as _;

        let mut out = Vec::new();
        self.body
            .read_to_end(&mut out)
            .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
        Ok(Bytes::from(out))
    }

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
    pub async fn bytes(self) -> Result<Bytes> {
        use futures_util::StreamExt as _;

        let mut out = Vec::new();
        let mut stream = self.body;
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(out))
    }

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

#[derive(Debug)]
pub struct HeadObjectOutput {
    pub etag: Option<String>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
}

#[derive(Debug)]
pub struct PutObjectOutput {
    pub etag: Option<String>,
}

#[cfg(feature = "checksums")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Sha1,
    Sha256,
}

#[cfg(feature = "checksums")]
impl ChecksumAlgorithm {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    pub algorithm: ChecksumAlgorithm,
    pub value: String,
}

#[cfg(feature = "checksums")]
impl Checksum {
    pub fn new(algorithm: ChecksumAlgorithm, value: impl Into<String>) -> Self {
        Self {
            algorithm,
            value: value.into(),
        }
    }

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

#[derive(Debug)]
pub struct DeleteObjectOutput;

#[derive(Debug)]
pub struct DeleteObjectsOutput {
    pub deleted: Vec<DeletedObject>,
    pub errors: Vec<DeleteObjectError>,
}

#[derive(Clone, Debug)]
pub struct DeleteObjectIdentifier {
    pub key: String,
    pub version_id: Option<String>,
}

impl DeleteObjectIdentifier {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            version_id: None,
        }
    }

    pub fn with_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }
}

#[derive(Debug)]
pub struct DeletedObject {
    pub key: Option<String>,
    pub version_id: Option<String>,
    pub delete_marker: Option<bool>,
    pub delete_marker_version_id: Option<String>,
}

#[derive(Debug)]
pub struct DeleteObjectError {
    pub key: Option<String>,
    pub version_id: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct CopyObjectOutput {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct CreateMultipartUploadOutput {
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub upload_id: String,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct UploadPartOutput {
    pub etag: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Clone, Debug)]
pub struct CompletedPart {
    pub part_number: u32,
    pub etag: String,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct CompleteMultipartUploadOutput {
    pub location: Option<String>,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub etag: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct AbortMultipartUploadOutput;

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct ListPartsOutput {
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub upload_id: Option<String>,
    pub is_truncated: bool,
    pub part_number_marker: Option<u32>,
    pub next_part_number_marker: Option<u32>,
    pub max_parts: Option<u32>,
    pub parts: Vec<Part>,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct Part {
    pub part_number: u32,
    pub etag: Option<String>,
    pub size: u64,
    pub last_modified: Option<String>,
}

#[cfg(feature = "multipart")]
#[derive(Debug)]
pub struct UploadPartCopyOutput {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub struct ListObjectsV2Output {
    pub name: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub is_truncated: bool,
    pub key_count: Option<u32>,
    pub max_keys: Option<u32>,
    pub continuation_token: Option<String>,
    pub next_continuation_token: Option<String>,
    pub contents: Vec<Object>,
    pub common_prefixes: Vec<String>,
}

#[derive(Debug)]
pub struct Object {
    pub key: String,
    pub size: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub storage_class: Option<String>,
}

#[derive(Debug)]
pub struct ListBucketsOutput {
    pub owner: Option<BucketOwner>,
    pub buckets: Vec<Bucket>,
}

#[derive(Debug)]
pub struct BucketOwner {
    pub id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug)]
pub struct Bucket {
    pub name: String,
    pub creation_date: Option<String>,
}

#[derive(Debug)]
pub struct HeadBucketOutput {
    pub region: Option<String>,
}

#[derive(Debug)]
pub struct CreateBucketOutput;

#[derive(Debug)]
pub struct DeleteBucketOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketVersioningConfiguration {
    pub status: Option<BucketVersioningStatus>,
    pub mfa_delete: Option<BucketMfaDeleteStatus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketVersioningStatus {
    Enabled,
    Suspended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketMfaDeleteStatus {
    Enabled,
    Disabled,
}

#[derive(Debug)]
pub struct PutBucketVersioningOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketLifecycleConfiguration {
    pub rules: Vec<BucketLifecycleRule>,
}

#[derive(Clone, Debug)]
pub struct BucketLifecycleRule {
    pub id: Option<String>,
    pub status: BucketLifecycleStatus,
    pub prefix: Option<String>,
    pub expiration_days: Option<u32>,
    pub expiration_date: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BucketLifecycleStatus {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Debug)]
pub struct PutBucketLifecycleOutput;

#[derive(Debug)]
pub struct DeleteBucketLifecycleOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketCorsConfiguration {
    pub rules: Vec<BucketCorsRule>,
}

#[derive(Clone, Debug)]
pub struct BucketCorsRule {
    pub id: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<CorsMethod>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorsMethod {
    Get,
    Put,
    Post,
    Delete,
    Head,
    Other(String),
}

impl CorsMethod {
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

#[derive(Debug)]
pub struct PutBucketCorsOutput;

#[derive(Debug)]
pub struct DeleteBucketCorsOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketTagging {
    pub tags: Vec<Tag>,
}

#[derive(Clone, Debug)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug)]
pub struct PutBucketTaggingOutput;

#[derive(Debug)]
pub struct DeleteBucketTaggingOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketEncryptionConfiguration {
    pub rules: Vec<BucketEncryptionRule>,
}

#[derive(Clone, Debug)]
pub struct BucketEncryptionRule {
    pub apply: ApplyServerSideEncryptionByDefault,
    pub bucket_key_enabled: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ApplyServerSideEncryptionByDefault {
    pub sse_algorithm: SseAlgorithm,
    pub kms_master_key_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseAlgorithm {
    Aes256,
    AwsKms,
    AwsKmsDsse,
    Other(String),
}

impl SseAlgorithm {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Aes256 => "AES256",
            Self::AwsKms => "aws:kms",
            Self::AwsKmsDsse => "aws:kms:dsse",
            Self::Other(v) => v.as_str(),
        }
    }
}

#[derive(Debug)]
pub struct PutBucketEncryptionOutput;

#[derive(Debug)]
pub struct DeleteBucketEncryptionOutput;

#[derive(Clone, Debug, Default)]
pub struct BucketPublicAccessBlockConfiguration {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[derive(Debug)]
pub struct PutBucketPublicAccessBlockOutput;

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
