//! A lean S3 client for Rust.
//!
//! ## Quick start (async)
//!
//! ```no_run
//! # #[cfg(feature = "async")]
//! # async fn demo() -> Result<(), s3::Error> {
//! use s3::{Auth, Client};
//!
//! let client = Client::builder("https://s3.amazonaws.com")?
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
//! let client = BlockingClient::builder("https://s3.amazonaws.com")?
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
//! See `docs/prd/prd.md`.

#[cfg(all(feature = "rustls", feature = "native-tls"))]
compile_error!("Enable only one of: rustls, native-tls.");

pub mod api;
#[cfg(feature = "providers")]
pub mod providers;
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
