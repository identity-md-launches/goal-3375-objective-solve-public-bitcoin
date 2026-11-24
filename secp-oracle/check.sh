#!/bin/sh
set -eu

cd "$(dirname "$0")"
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
trap 'exit 1' HUP INT TERM

vendor="$PWD/vendor/secp256k1"
(cd "$vendor" && sha256sum --quiet -c ../../vendor.sha256)
cc -std=c99 -O2 -fPIC -shared -Wall -Wextra -Werror -Wno-unused-function \
    -DUSE_FORCE_WIDEMUL_INT64 -DECMULT_WINDOW_SIZE=5 \
    -I"$vendor/include" oracle.c "$vendor/src/secp256k1.c" \
    "$vendor/src/precomputed_ecmult.c" "$vendor/src/precomputed_ecmult_gen.c" \
    -o "$build/oracle.so"

python3 -I -B oracle.py "$build/oracle.so" "$@"
