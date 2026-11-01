#!/usr/bin/env bash
# The workspace test suite split in two (owner's decision 26.10: two thirds on
# Hermes, one third in the cloud). Measured 26.10: the three slow test files of
# ksg-cli-v2 (cli, base, devnet) take 2/3 of the time.
#
#   scripts/test_split.sh hermes   # ksg-cli-v2: cli, base, devnet
#   scripts/test_split.sh cloud    # everything else
#
# Uses cargo-nextest when present (parallel across test files), plain cargo test otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
SLOW='package(ksg-cli-v2) & (binary(cli) | binary(base) | binary(devnet))'
case "${1:?hermes|cloud}" in
  hermes)
    if cargo nextest --version >/dev/null 2>&1; then
      cargo nextest run --workspace --no-fail-fast -E "$SLOW"
    else
      cargo test -q -p ksg-cli-v2 --test cli --test base --test devnet
    fi ;;
  cloud)
    if cargo nextest --version >/dev/null 2>&1; then
      cargo nextest run --workspace --no-fail-fast -E "not ($SLOW)"
    else
      echo "cloud third needs cargo-nextest (cargo install cargo-nextest --locked)"; exit 2
    fi ;;
  *) echo "usage: $0 hermes|cloud"; exit 2 ;;
esac
