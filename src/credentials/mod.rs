#[cfg(feature = "credentials-imds")]
pub(crate) mod imds;
#[cfg(feature = "credentials-profile")]
pub(crate) mod profile;
#[cfg(feature = "credentials-sts")]
pub(crate) mod sts;
