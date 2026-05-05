# Contributing

## Setup

```bash
git clone https://github.com/thepictishbeast/plausiden-identity.git
cd plausiden-identity
cargo test
```

## Standards

- `cargo fmt` before committing
- `cargo clippy -- -D warnings` must pass
- Every public function needs a doc comment
- Every bug fix needs a regression test
- No `unwrap()` in library code without safety comment
- All secret material must use the `zeroize` crate

## Pull Requests

- One logical change per PR
- Include tests for new functionality
- Update CHANGELOG.md for significant changes
