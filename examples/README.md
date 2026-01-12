# Examples

All examples are runnable and meant to be read as usage docs.

## Local / S3-compatible endpoint

Most async examples support:

- `S3_TEST_ENDPOINT` (e.g. `http://127.0.0.1:9000`)
- `S3_TEST_REGION` (default: `us-east-1`)
- `S3_TEST_BUCKET` (required for object ops)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`

## Index

- `async_put_get_delete.rs`: basic put/get/head/delete
- `async_put_stream.rs`: streaming upload (requires `Content-Length`)
- `async_list_buckets.rs`: list buckets
- `async_list_objects.rs`: list objects v2 + pagination
- `async_delete_objects_batch.rs`: batch delete (Content-MD5 included)
- `async_copy_object.rs`: copy object + replace metadata
- `async_multipart_upload.rs`: multipart upload (`--features multipart`)
- `presign_get.rs`: presign with static credentials
- `async_presign_build_async.rs`: presign with a credentials provider (`build_async`)
- `async_auth_imds.rs`: IMDS credentials (`--features credentials-imds`)
- `async_auth_web_identity.rs`: web identity credentials (`--features credentials-sts`)
- `blocking_put_get_delete.rs`: blocking put/get/delete
- `blocking_list_buckets.rs`: blocking list buckets
- `blocking_presign_get.rs`: blocking presign with static credentials
- `minio_local_put_get_delete.rs`: `providers::minio_local()` preset (`--features providers`)
- `r2_put_get_delete.rs`: Cloudflare R2 preset (`--features providers`)
  - Optional: `R2_JURISDICTION` (e.g. `eu`, `fedramp`) for jurisdiction-restricted buckets
