# List available recipes.
default:
    @just --list

# Run all tests in the workspace.
test:
    cargo test --workspace --all-targets

# Run clippy and fail on any warning.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Format all code.
fmt:
    cargo fmt --all

# Check formatting without changing files (for CI).
fmt-check:
    cargo fmt --all -- --check

# Run benchmarks.
bench:
    cargo bench --workspace
