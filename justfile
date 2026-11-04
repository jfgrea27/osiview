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

# Linux container for live capture (AF_PACKET is Linux-only). Build output and
# the crate cache live in Docker volumes so they don't clash with macOS's target/.
docker_linux := 'docker run --rm -it --cap-add NET_RAW -v "$PWD":/src -w /src -v osiview-target:/src/target -v osiview-cargo:/usr/local/cargo/registry rust:1'

# Run any cargo command in the Linux container, e.g. `just linux test`.
linux *args:
    {{docker_linux}} cargo {{args}}

# Run osiview in the Linux container, e.g. `just osiview capture -i eth0 -c 10`.
osiview *args:
    {{docker_linux}} cargo run -q -- {{args}}

# End to end: request a URL and print every packet it caused, L2 → L7.
# `just e2e`, `just e2e http://example.com -p` (payloads), `-v` (field tables), `-w out.pcap`.
e2e url="http://example.com" *flags:
    {{docker_linux}} cargo run -q -- {{url}} {{flags}}

# Lint and test on Linux, where the capture code is compiled (CI runs Linux too).
linux-check:
    {{docker_linux}} sh -c 'rustup component add clippy >/dev/null 2>&1 && cargo clippy --all-targets -- -D warnings && cargo test'
