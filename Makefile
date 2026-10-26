# Phantom Key v2 Makefile

.PHONY: all build test run clean format lint clippy

# Build
build:
	cargo build --release

# Test
test:
	cargo test --all

# Run
run:
	cargo run --release

# Run with config
run-config:
	cargo run --release -- --config config.yaml

# Clean
clean:
	cargo clean
	rm -rf keys/

# Format
format:
	cargo fmt

# Lint
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Clippy
clippy:
	cargo clippy --all-targets --all-features

# Generate keys
gen-keys:
	cargo run --release -- generate-keys --parties 5 --threshold 3

# Attack Lab
attack-lab:
	cargo run --release -- attack-lab

# Run all
all: build test

# Documentation
docs:
	cargo doc --open

# Benchmark
bench:
	cargo bench

# Coverage
coverage:
	cargo tarpaulin --all

# Release
release:
	cargo build --release
	mkdir -p release
	cp target/release/phantom-key release/
	cp README.md release/
	cp LICENSE release/
	tar czf release/phantom-key-v2.tar.gz -C release .
