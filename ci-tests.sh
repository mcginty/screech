#!/usr/bin/env bash
set -e
TARGET="$([ -n "$1" ] && echo "--target $1" || echo "")"

COMMON_FEATURES="xchachapoly vector-tests"

set -x
cargo check --benches
cargo test $TARGET --no-default-features
cargo test $TARGET --features "$COMMON_FEATURES"
cargo test $TARGET --features "ring-resolver $COMMON_FEATURES"
cargo test $TARGET --features "ring-accelerated $COMMON_FEATURES"
cargo test $TARGET --features "hfs nist3_kyber1024 $COMMON_FEATURES"
cargo test $TARGET --features "ring-resolver hfs nist3_kyber1024 $COMMON_FEATURES"
cargo test $TARGET --features "libsodium-resolver $COMMON_FEATURES"
cargo test $TARGET --features "libsodium-accelerated $COMMON_FEATURES"
