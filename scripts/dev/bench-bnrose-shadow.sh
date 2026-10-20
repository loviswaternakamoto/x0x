#!/usr/bin/env bash
# Offline only. No daemon, sockets, identity store or production configuration.
set -euo pipefail
cd "$(dirname "$0")/../.."
output="${1:?usage: bench-bnrose-shadow.sh ABSOLUTE_OUTPUT_DIRECTORY}"
case "$output" in /*) ;; *) echo 'output must be an absolute path' >&2; exit 2;; esac
if test -e "$output"; then echo 'refusing to overwrite an existing receipt' >&2; exit 2; fi
mkdir -p "$output"
git rev-parse HEAD > "$output/revision.txt"
git status --porcelain > "$output/worktree-status.txt"
git diff --binary HEAD > "$output/source-diff.patch"
sha256sum Cargo.toml Cargo.lock src/bnrose_shadow.rs examples/bnrose_shadow.rs > "$output/source-sha256.txt"
rustc +1.95.0 -Vv > "$output/rustc.txt"
uname -a > "$output/kernel.txt"
cat /etc/os-release > "$output/os-release.txt"
lscpu > "$output/cpu.txt"
cargo +1.95.0 test --locked --features bnrose-shadow --example bnrose_shadow > "$output/tests.log" 2>&1
cargo +1.95.0 build --locked --release --features bnrose-shadow --example bnrose_shadow > "$output/build.log" 2>&1
binary="${CARGO_TARGET_DIR:-target}/release/examples/bnrose_shadow"
sha256sum "$binary" > "$output/binary-sha256.txt"
time_bin="$(type -P time)"
"$time_bin" -v -o "$output/process-time.txt" "$binary" > "$output/measurement.json"
echo "Offline receipt: $output"
