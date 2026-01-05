use base64::Engine as _;
use http::HeaderValue;

use crate::{Result, error::Error};

pub(crate) fn content_md5_header_value(bytes: &[u8]) -> Result<HeaderValue> {
    use md5::Digest as _;

    let digest = md5::Md5::digest(bytes);
    let value = base64::engine::general_purpose::STANDARD.encode(digest);
    HeaderValue::from_str(&value).map_err(|_| Error::invalid_config("invalid Content-MD5 header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_md5_in_base64() {
        let hv = content_md5_header_value(b"").unwrap();
        assert_eq!(hv.to_str().unwrap(), "1B2M2Y8AsgTpgAmY7PhCfg==");
    }
}
