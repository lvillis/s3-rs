set shell := ["bash", "-euo", "pipefail", "-c"]

ci:
    cargo fmt --all --check
    cargo check --lib --no-default-features
    cargo nextest run --lib --no-default-features
    cargo nextest run --lib --no-default-features --features providers
    cargo check --lib
    cargo check --all-features
    RUSTFLAGS='-Dmissing_docs' cargo check --lib --all-features
    RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
    cargo test --doc --all-features
    cargo check --lib --no-default-features --features blocking,rustls
    cargo nextest run --lib
    cargo clippy --all-targets --all-features -- -D warnings
    cargo clippy --all-targets --no-default-features -- -D warnings
    cargo clippy --all-targets --no-default-features --features blocking,rustls -- -D warnings

patch:
    cargo release patch --no-publish --execute

