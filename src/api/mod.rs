#[cfg(feature = "blocking")]
mod blocking_buckets;
#[cfg(feature = "blocking")]
mod blocking_objects;
#[cfg(feature = "async")]
mod buckets;
#[cfg(feature = "async")]
mod objects;

#[cfg(feature = "async")]
pub use buckets::{
    BucketsService, CreateBucketRequest, DeleteBucketConfigRawRequest, DeleteBucketCorsRequest,
    DeleteBucketEncryptionRequest, DeleteBucketLifecycleRequest,
    DeleteBucketPublicAccessBlockRequest, DeleteBucketRequest, DeleteBucketTaggingRequest,
    GetBucketConfigRawRequest, GetBucketCorsRequest, GetBucketEncryptionRequest,
    GetBucketLifecycleRequest, GetBucketPublicAccessBlockRequest, GetBucketTaggingRequest,
    GetBucketVersioningRequest, HeadBucketRequest, ListBucketsRequest, PutBucketConfigRawRequest,
    PutBucketCorsRequest, PutBucketEncryptionRequest, PutBucketLifecycleRequest,
    PutBucketPublicAccessBlockRequest, PutBucketTaggingRequest, PutBucketVersioningRequest,
};

#[cfg(feature = "async")]
pub use objects::{
    CopyObjectRequest, DeleteObjectRequest, DeleteObjectsRequest, GetObjectRequest,
    HeadObjectRequest, ListObjectsV2Pager, ListObjectsV2Request, ObjectsService,
    PresignDeleteObjectRequest, PresignGetObjectRequest, PresignHeadObjectRequest,
    PresignObjectRequest, PresignPutObjectRequest, PutObjectRequest,
};

#[cfg(all(feature = "async", feature = "multipart"))]
pub use objects::{
    AbortMultipartUploadRequest, CompleteMultipartUploadRequest, CreateMultipartUploadRequest,
    ListPartsRequest, UploadPartCopyRequest, UploadPartRequest,
};

#[cfg(feature = "blocking")]
pub use blocking_buckets::{
    BlockingBucketsService, BlockingCreateBucketRequest, BlockingDeleteBucketConfigRawRequest,
    BlockingDeleteBucketCorsRequest, BlockingDeleteBucketEncryptionRequest,
    BlockingDeleteBucketLifecycleRequest, BlockingDeleteBucketPublicAccessBlockRequest,
    BlockingDeleteBucketRequest, BlockingDeleteBucketTaggingRequest,
    BlockingGetBucketConfigRawRequest, BlockingGetBucketCorsRequest,
    BlockingGetBucketEncryptionRequest, BlockingGetBucketLifecycleRequest,
    BlockingGetBucketPublicAccessBlockRequest, BlockingGetBucketTaggingRequest,
    BlockingGetBucketVersioningRequest, BlockingHeadBucketRequest, BlockingListBucketsRequest,
    BlockingPutBucketConfigRawRequest, BlockingPutBucketCorsRequest,
    BlockingPutBucketEncryptionRequest, BlockingPutBucketLifecycleRequest,
    BlockingPutBucketPublicAccessBlockRequest, BlockingPutBucketTaggingRequest,
    BlockingPutBucketVersioningRequest,
};

#[cfg(feature = "blocking")]
pub use blocking_objects::{
    BlockingCopyObjectRequest, BlockingDeleteObjectRequest, BlockingDeleteObjectsRequest,
    BlockingGetObjectRequest, BlockingHeadObjectRequest, BlockingListObjectsV2Pager,
    BlockingListObjectsV2Request, BlockingObjectsService, BlockingPresignDeleteObjectRequest,
    BlockingPresignGetObjectRequest, BlockingPresignHeadObjectRequest,
    BlockingPresignObjectRequest, BlockingPresignPutObjectRequest, BlockingPutObjectRequest,
};

#[cfg(all(feature = "blocking", feature = "multipart"))]
pub use blocking_objects::{
    BlockingAbortMultipartUploadRequest, BlockingCompleteMultipartUploadRequest,
    BlockingCreateMultipartUploadRequest, BlockingListPartsRequest, BlockingUploadPartCopyRequest,
    BlockingUploadPartRequest,
};
