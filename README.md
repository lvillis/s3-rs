# s3-rs

[![crates.io](https://img.shields.io/crates/v/s3.svg)](https://crates.io/crates/s3)
[![docs.rs](https://docs.rs/s3/badge.svg)](https://docs.rs/s3)
[![CI](https://github.com/lvillis/s3-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/lvillis/s3-rs/actions/workflows/ci.yaml)

Lean, modern, unofficial S3-compatible client for Rust.

## Highlights

- Async + blocking clients (consistent API shape)
- Presigned URLs and multipart upload
- Optional checksums, tracing, and metrics
- Integration-tested against MinIO and RustFS
- Small dependency surface (feature-gated)
- Structured errors (status/code/request id/body snippet)

## Install

```bash
# async + rustls (default)
cargo add s3

# blocking (disable defaults, pick one TLS backend)
cargo add s3 --no-default-features --features blocking,rustls

# async + native-tls
cargo add s3 --no-default-features --features async,native-tls
```

MSRV: Rust `1.92`.

## Usage

### Async

```rust,no_run
use s3::{Auth, Client};

# async fn demo() -> Result<(), s3::Error> {
let client = Client::builder("https://s3.example.com")?
    .region("us-east-1")
    .auth(Auth::from_env()?)
    .build()?;

let obj = client.objects().get("my-bucket", "path/to/object.txt").send().await?;
let bytes = obj.bytes().await?;
println!("{} bytes", bytes.len());
# Ok(())
# }
```

`Auth::from_env()` reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`.

### Blocking

```rust,no_run
use s3::{Auth, BlockingClient};

fn demo() -> Result<(), s3::Error> {
    let client = BlockingClient::builder("https://s3.example.com")?
        .region("us-east-1")
        .auth(Auth::from_env()?)
        .build()?;

    let obj = client.objects().get("my-bucket", "path/to/object.txt").send()?;
    let bytes = obj.bytes()?;
    println!("{} bytes", bytes.len());
    Ok(())
}
```

### Configuration

```rust,no_run
use std::time::Duration;

use s3::{AddressingStyle, Auth, Client};

# async fn demo() -> Result<(), s3::Error> {
let client = Client::builder("https://s3.example.com")?
    .region("us-east-1")
    .auth(Auth::from_env()?)
    .addressing_style(AddressingStyle::Auto)
    .timeout(Duration::from_secs(30))
    .max_attempts(3)
    .build()?;
# Ok(())
# }
```

### Presign

```rust,no_run
use s3::{Auth, Client};

# async fn demo() -> Result<(), s3::Error> {
let client = Client::builder("https://s3.example.com")?
    .region("us-east-1")
    .auth(Auth::from_env()?)
    .build()?;

let presigned = client
    .objects()
    .presign_get("my-bucket", "path/to/object.txt")
    .build()?;

println!("GET {}", presigned.url);
# Ok(())
# }
```

### Endpoint presets (feature = `providers`)

```rust,no_run
use s3::{Auth, providers};

# async fn demo() -> Result<(), s3::Error> {
let preset = providers::minio_local();
let client = preset
    .async_client_builder()?
    .auth(Auth::from_env()?)
    .build()?;
# Ok(())
# }
```

## Authentication

- `Auth::Anonymous`: unsigned requests (for public buckets / anonymous endpoints)
- `Auth::from_env()`: static credentials from env vars
- `Auth::provider(...)`: plug in your own refreshable provider (cached/singleflight refresh)
- Optional features:
  - `credentials-profile`: shared config/profile loader
  - `credentials-imds`: IMDS credentials (async/blocking APIs)
  - `credentials-sts`: web identity / STS flows

## Compatibility

- Addressing styles: `AddressingStyle::Auto` (default), `Path`, `VirtualHosted`
- Targets: any S3-compatible service; CI runs against MinIO and RustFS

## Feature flags

- Modes: `async` (default), `blocking`
- TLS: `rustls` (default), `native-tls`
- Optional: `multipart`, `checksums`, `providers`, `credentials-profile`, `credentials-imds`, `credentials-sts`, `tracing`, `metrics`

## Examples

- Basic put/get/delete: `examples/async_put_get_delete.rs`
- Streaming upload (requires Content-Length): `examples/async_put_stream.rs`
- List objects v2 + pagination: `examples/async_list_objects.rs`
- Multipart upload (feature = `multipart`): `examples/async_multipart_upload.rs`
- Presign: `examples/presign_get.rs`, `examples/async_presign_build_async.rs`
- Blocking: `examples/blocking_put_get_delete.rs`
- More: `examples/README.md`
