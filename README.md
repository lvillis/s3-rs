# s3-rs

[![crates.io](https://img.shields.io/crates/v/s3.svg)](https://crates.io/crates/s3)
[![docs.rs](https://docs.rs/s3/badge.svg)](https://docs.rs/s3)
[![CI](https://github.com/lvillis/s3-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lvillis/s3-rs/actions/workflows/ci.yml)

A lean, modern, unofficial S3-compatible client for Rust.

## Quick start (async)

```rust,no_run
use s3::{Auth, Client};

# async fn demo() -> Result<(), s3::Error> {
let client = Client::builder("https://s3.amazonaws.com")?
    .region("us-east-1")
    .auth(Auth::from_env()?)
    .build()?;

let obj = client.objects().get("my-bucket", "path/to/object.txt").send().await?;
let bytes = obj.bytes().await?;
println!("{} bytes", bytes.len());
# Ok(())
# }
```

## Blocking

Enable `blocking` and choose one TLS backend (`rustls` or `native-tls`):

```bash
cargo add s3 --no-default-features --features blocking,rustls
```

```rust,no_run
use s3::{Auth, BlockingClient};

fn demo() -> Result<(), s3::Error> {
    let client = BlockingClient::builder("https://s3.amazonaws.com")?
        .region("us-east-1")
        .auth(Auth::from_env()?)
        .build()?;

    let obj = client.objects().get("my-bucket", "path/to/object.txt").send()?;
    let bytes = obj.bytes()?;
    println!("{} bytes", bytes.len());
    Ok(())
}
```

## Features

- `async` (default), `blocking`
- `multipart`, `checksums`, `tracing`, `metrics`

MSRV: Rust `1.92`.
