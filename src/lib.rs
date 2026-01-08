//! A lean S3 client for Rust.
//!
//! ## Quick start (async)
//!
//! ```no_run
//! # #[cfg(feature = "async")]
//! # async fn demo() -> Result<(), s3::Error> {
//! use s3::{Auth, Client};
//!
//! let client = Client::builder("https://s3.example.com")?
//!     .region("us-east-1")
//!     .auth(Auth::from_env()?)
//!     .build()?;
//!
//! let obj = client
//!     .objects()
//!     .get("my-bucket", "path/to/object.txt")
//!     .send()
//!     .await?;
//! let bytes = obj.bytes().await?;
//! println!("{} bytes", bytes.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Quick start (blocking)
//!
//! ```no_run
//! # #[cfg(feature = "blocking")]
//! # fn demo() -> Result<(), s3::Error> {
//! use s3::{Auth, BlockingClient};
//!
//! let client = BlockingClient::builder("https://s3.example.com")?
//!     .region("us-east-1")
//!     .auth(Auth::from_env()?)
//!     .build()?;
//!
//! let obj = client.objects().get("my-bucket", "path/to/object.txt").send()?;
//! let bytes = obj.bytes()?;
//! println!("{} bytes", bytes.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Design
//!
//! See README for product intent and usage.

#[cfg(all(
    feature = "rustls",
    feature = "native-tls",
    not(feature = "allow-both-tls")
))]
compile_error!("Enable only one of: rustls, native-tls.");

/// Service entry points and request builders.
pub mod api;
#[cfg(feature = "providers")]
/// Endpoint presets for common S3-compatible services.
pub mod providers;
/// Shared request/response types.
pub mod types;

mod auth;
mod client;
mod credentials;
mod error;
mod transport;
mod util;

pub use auth::{
    AddressingStyle, Auth, CachedProvider, Credentials, CredentialsProvider, CredentialsSnapshot,
    DynCredentialsProvider, Region,
};
#[cfg(feature = "blocking")]
pub use client::{BlockingClient, BlockingClientBuilder};
#[cfg(feature = "async")]
pub use client::{Client, ClientBuilder};
pub use error::{Error, Result};
