## [0.1.20] - 2026-03-06

### 🐛 Bug Fixes

- Restore no-default-features test compatibility

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.20
## [0.1.19] - 2026-03-06

### 🐛 Bug Fixes

- Harden feature gating, add blocking reader uploads

### 🚜 Refactor

- Adopt reqx-native transport flow

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.19
## [0.1.18] - 2026-03-04

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.18
## [0.1.17] - 2026-02-25

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.17
## [0.1.16] - 2026-02-24

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.16
## [0.1.15] - 2026-02-13

### 🐛 Bug Fixes

- *(infra)* Dedupe CI runs and resolve clippy warnings

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.15
## [0.1.14] - 2026-02-13

### 🐛 Bug Fixes

- *(store)* Harden reqx redirect checks and S3 request validation
- *(store)* Enforce strict redirect URI query matching
- Harden transport error handling and unify shared API validation helpers
- *(store)* Harden retry/presign guards and dedupe transport/client
- *(store)* Harden retry-after cap, error redaction and dual-mode refresh
- *(store)* Harden retry/trace redaction and rate-limit error mapping
- *(store)* Tighten host redaction, service error metrics, and async presign guidance
- *(store)* Reject endpoint userinfo and redact s3.request host

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.14
## [0.1.13] - 2026-02-12

### 🐛 Bug Fixes

- *(store)* Avoid false redirect errors when query is omitted

### ⚙️ Miscellaneous Tasks

- Fmt
- Release s3 version 0.1.13
## [0.1.12] - 2026-02-12

### 🐛 Bug Fixes

- *(store)* Align reqx transport semantics and add regression tests
- *(store)* Harden reqx retries, XML error parsing and IMDS fallback

### ⚙️ Miscellaneous Tasks

- Update Cargo.toml
- Release s3 version 0.1.12
## [0.1.11] - 2026-02-11

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.11
## [0.1.10] - 2026-02-11

### 🐛 Bug Fixes

- *(transport)* Add HEAD content-encoding regression coverage for async and blocking

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.10
## [0.1.9] - 2026-02-11

### 🚀 Features

- *(store)* Switch transport to reqx with configurable TLS root stores

### 🧪 Testing

- *(store)* Add TLS root-store coverage for client and credential flows

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.9
## [0.1.8] - 2026-01-12

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.8
## [0.1.7] - 2026-01-12

### 🚀 Features

- *(providers)* Add typed R2 endpoints with jurisdiction support

### ⚙️ Miscellaneous Tasks

- Release s3 version 0.1.7
## [0.1.6] - 2026-01-08

### ⚙️ Miscellaneous Tasks

- *(docs)* Expand rustdoc coverage and stabilize all-features tests
- Release s3 version 0.1.6
## [0.1.5] - 2026-01-06

### 🧪 Testing

- Fix MinIO virtual-hosted integration by creating buckets via path-style
- *(store)* Rename and stabilize s3_compat integration tests
- *(store)* Make s3_compat tests strictness configurable

### ⚙️ Miscellaneous Tasks

- *(ci)* Update ci.yaml
- *(ci)* Set MINIO_DOMAIN for vhost tests
- Release s3 version 0.1.4
- Add rustfs integration tests
- Release s3 version 0.1.5
## [0.1.3] - 2026-01-06

### 🚀 Features

- *(providers)* Add rule-based presets and AwsRegion helpers
- *(auth)* Add credential providers with cached auto-refresh

### 🐛 Bug Fixes

- *(ci)* Make async streaming PUT sized and skip unsupported bucket config ops
- Add Content-MD5 for bucket config PUT requests

### 🧪 Testing

- Harden MinIO integration suite
- *(ci)* Skip unsupported bucket config ops in MinIO integration
- Expand coverage for cached credentials, transport, and MinIO vhost

### ⚙️ Miscellaneous Tasks

- *(bench)* Add criterion microbench suite
- Release s3 version 0.1.2
- *(examples)* Add practical async/blocking usage examples
- *(ci)* Update
- *(examples)* Add more runnable usage guides
- Release s3 version 0.1.3
## [0.1.1] - 2026-01-05

### 🐛 Bug Fixes

- Ci
- *(ci)* Add Content-MD5 for DeleteObjects and make multipart test S3-compliant
- *(blocking)* Treat non-2xx responses as API errors

### 🚜 Refactor

- Harden blocking retries, add native-tls CI, and dedupe api helpers

### ⚙️ Miscellaneous Tasks

- Init commit
- Update Cargo.toml
- Release s3 version 0.1.1
