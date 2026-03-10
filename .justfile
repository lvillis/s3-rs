set shell := ["bash", "-euo", "pipefail", "-c"]

ci:
    cargo fmt --all --check
    cargo check --lib --no-default-features
    cargo test --lib --no-default-features
    cargo test --lib --no-default-features --features providers
    cargo check --lib
    cargo check --all-features
    cargo check --lib --no-default-features --features blocking,rustls
    cargo test --lib
    cargo clippy --all-targets --all-features -- -D warnings
    cargo clippy --all-targets --no-default-features -- -D warnings
    cargo clippy --all-targets --no-default-features --features blocking,rustls -- -D warnings
