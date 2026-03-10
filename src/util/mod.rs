#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod encode;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod headers;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod md5;
pub(crate) mod redact;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod signing;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod text;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod url;
#[cfg(any(test, feature = "async", feature = "blocking"))]
pub(crate) mod xml;
