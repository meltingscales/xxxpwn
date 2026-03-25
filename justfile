# xxxpwn justfile

# Default: show available recipes
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# Check for compile errors without producing a binary
check:
    cargo check

# Run tests
test:
    cargo test

# Clean build artifacts
clean:
    cargo clean

# Install binary to ~/.cargo/bin
install:
    cargo install --path .

# Run with provided arguments (e.g.: just run -- -i inject.txt -m match host 80)
run *ARGS:
    cargo run --release -- {{ARGS}}

# Lint with clippy
lint:
    cargo clippy -- -D warnings

# Format source code
fmt:
    cargo fmt
