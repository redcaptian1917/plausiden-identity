test:
    cargo test

test-verbose:
    cargo test -- --nocapture

fmt:
    cargo fmt

lint:
    cargo clippy -- -D warnings

build:
    cargo build --release

run:
    cargo run --features server

docs:
    cargo doc --no-deps --open

audit:
    cargo audit

bench:
    cargo bench

check-all: fmt lint test build
