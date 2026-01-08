//! Endpoint presets for common S3-compatible services.

use crate::{AddressingStyle, Error, Result};

/// Common AWS regions for presets.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AwsRegion {
    /// us-east-1
    UsEast1,
    /// us-west-2
    UsWest2,
    /// eu-west-1
    EuWest1,
    /// ap-southeast-1
    ApSoutheast1,
    /// Custom region string.
    Other(String),
}

impl AwsRegion {
    /// Creates a custom region variant.
    pub fn other(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::invalid_config("region must not be empty"));
        }
        Ok(Self::Other(value))
    }

    /// Returns the region identifier.
    pub fn as_str(&self) -> &str {
        match self {
            Self::UsEast1 => "us-east-1",
            Self::UsWest2 => "us-west-2",
            Self::EuWest1 => "eu-west-1",
            Self::ApSoutheast1 => "ap-southeast-1",
            Self::Other(v) => v,
        }
    }
}

impl std::str::FromStr for AwsRegion {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::invalid_config("region must not be empty"));
        }
        Ok(match value {
            "us-east-1" => Self::UsEast1,
            "us-west-2" => Self::UsWest2,
            "eu-west-1" => Self::EuWest1,
            "ap-southeast-1" => Self::ApSoutheast1,
            other => Self::Other(other.to_string()),
        })
    }
}

/// A preconfigured endpoint + region + addressing style.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    endpoint: String,
    region: String,
    addressing_style: AddressingStyle,
}

impl Preset {
    /// Returns the service endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the signing region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the addressing style to use.
    pub fn addressing_style(&self) -> AddressingStyle {
        self.addressing_style
    }

    /// Builds an async client builder from the preset.
    #[cfg(feature = "async")]
    pub fn async_client_builder(&self) -> Result<crate::ClientBuilder> {
        crate::Client::builder(&self.endpoint).map(|b| {
            b.region(self.region.clone())
                .addressing_style(self.addressing_style)
        })
    }

    /// Builds a blocking client builder from the preset.
    #[cfg(feature = "blocking")]
    pub fn blocking_client_builder(&self) -> Result<crate::BlockingClientBuilder> {
        crate::BlockingClient::builder(&self.endpoint).map(|b| {
            b.region(self.region.clone())
                .addressing_style(self.addressing_style)
        })
    }
}

/// Builds a preset for AWS S3.
pub fn aws_s3(region: impl AsRef<str>) -> Result<Preset> {
    let region = region.as_ref().trim();
    if region.is_empty() {
        return Err(Error::invalid_config("region must not be empty"));
    }

    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };

    let endpoint = if region == "us-east-1" && suffix == "amazonaws.com" {
        "https://s3.amazonaws.com".to_string()
    } else {
        format!("https://s3.{region}.{suffix}")
    };

    Ok(Preset {
        endpoint,
        region: region.to_string(),
        addressing_style: AddressingStyle::Auto,
    })
}

/// Builds a preset for AWS S3 using a typed region.
pub fn aws_s3_region(region: AwsRegion) -> Result<Preset> {
    aws_s3(region.as_str())
}

/// Builds a preset for Cloudflare R2.
pub fn cloudflare_r2(account_id: impl AsRef<str>) -> Result<Preset> {
    let account_id = account_id.as_ref().trim();
    if account_id.is_empty() {
        return Err(Error::invalid_config("account_id must not be empty"));
    }

    Ok(Preset {
        endpoint: format!("https://{account_id}.r2.cloudflarestorage.com"),
        region: "auto".to_string(),
        addressing_style: AddressingStyle::Path,
    })
}

/// Local MinIO preset for development.
pub fn minio_local() -> Preset {
    Preset {
        endpoint: "http://127.0.0.1:9000".to_string(),
        region: "us-east-1".to_string(),
        addressing_style: AddressingStyle::Path,
    }
}

pub mod aws {
    use super::{AwsRegion, Preset, Result, aws_s3_region};

    /// us-east-1.
    pub const US_EAST_1: AwsRegion = AwsRegion::UsEast1;
    /// us-west-2.
    pub const US_WEST_2: AwsRegion = AwsRegion::UsWest2;
    /// eu-west-1.
    pub const EU_WEST_1: AwsRegion = AwsRegion::EuWest1;
    /// ap-southeast-1.
    pub const AP_SOUTHEAST_1: AwsRegion = AwsRegion::ApSoutheast1;

    /// Builds an AWS S3 preset from a typed region.
    pub fn s3(region: AwsRegion) -> Result<Preset> {
        aws_s3_region(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_r2_uses_path_and_auto_region() {
        let preset = cloudflare_r2("123").unwrap();
        assert_eq!(preset.endpoint(), "https://123.r2.cloudflarestorage.com");
        assert_eq!(preset.region(), "auto");
        assert_eq!(preset.addressing_style(), AddressingStyle::Path);
    }

    #[test]
    fn aws_s3_uses_us_east_1_global_endpoint() {
        let preset = aws_s3("us-east-1").unwrap();
        assert_eq!(preset.endpoint(), "https://s3.amazonaws.com");
        assert_eq!(preset.region(), "us-east-1");
        assert_eq!(preset.addressing_style(), AddressingStyle::Auto);
    }

    #[test]
    fn aws_s3_cn_uses_cn_suffix() {
        let preset = aws_s3("cn-north-1").unwrap();
        assert_eq!(preset.endpoint(), "https://s3.cn-north-1.amazonaws.com.cn");
    }

    #[test]
    fn aws_region_parses_common_ids() {
        assert_eq!(
            "us-east-1".parse::<AwsRegion>().unwrap(),
            AwsRegion::UsEast1
        );
        assert_eq!(
            "unknown-1".parse::<AwsRegion>().unwrap(),
            AwsRegion::Other("unknown-1".to_string())
        );
    }

    #[test]
    fn aws_s3_region_works() {
        let preset = aws_s3_region(AwsRegion::UsEast1).unwrap();
        assert_eq!(preset.endpoint(), "https://s3.amazonaws.com");
    }
}
