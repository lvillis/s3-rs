use std::io::Read;

use crate::error::{Error, Result};

pub(crate) fn read_body_bytes(body: ureq::Body) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    body.into_reader()
        .read_to_end(&mut out)
        .map_err(|e| Error::transport("failed to read response body", Some(Box::new(e))))?;
    Ok(out)
}

pub(crate) fn read_body_string(body: ureq::Body) -> Result<String> {
    let bytes = read_body_bytes(body)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
