#!/usr/bin/env bash
set -euo pipefail
echo "=== fmt ==="
cargo fmt --check
echo "=== test ==="
cargo test --lib --tests
echo "=== clippy ==="
cargo clippy -- -D warnings
echo "=== all green ==="
