#!/usr/bin/env bash
# Reproducible OPTIONAL CUDA source-build recipe for the vendored, patched
# RCKangaroo adapter. Run ONLY on an entrant-controlled host that already has a
# compatible NVIDIA GPU and CUDA Toolkit. This script inventories nothing, rents
# nothing, and downloads nothing; it builds the vendored source in place.
#
# Prerequisites (must already be present; this script does not install them):
#   - CUDA Toolkit (nvcc), version compatible with the vendored CMakeLists.txt
#     (upstream pins CUDAToolkit_ROOT to /usr/local/cuda-12.8; override below).
#   - A C++20 host compiler and CMake >= 3.17.
#   - An NVIDIA GPU whose compute capability is in the gencode list
#     (CMakeLists.txt: sm_61/75/86/89). Turbo kernels for sm_89/sm_120 need the
#     excluded .cubin files; see PROVENANCE.json.
#
# Usage:
#   CUDA_ROOT=/usr/local/cuda-12.8 bash rckangaroo/build/build_cuda.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)/upstream"
BUILD="${BUILD_DIR:-$SRC/build-cuda}"
CUDA_ROOT="${CUDA_ROOT:-/usr/local/cuda-12.8}"

echo "[build_cuda] source dir : $SRC"
echo "[build_cuda] build dir  : $BUILD"
echo "[build_cuda] CUDA root  : $CUDA_ROOT"

if ! command -v cmake >/dev/null 2>&1; then
  echo "[build_cuda] ERROR: cmake not found (prerequisite unmet)." >&2
  exit 3
fi
if [ ! -x "$CUDA_ROOT/bin/nvcc" ]; then
  echo "[build_cuda] ERROR: nvcc not found at $CUDA_ROOT/bin/nvcc (prerequisite unmet)." >&2
  echo "[build_cuda] Set CUDA_ROOT to your CUDA Toolkit, e.g. CUDA_ROOT=/usr/local/cuda-12.x" >&2
  exit 3
fi

# Verify the vendored source still matches the shipped hashes before building.
( cd "$(cd "$HERE/.." && pwd)" && sha256sum -c --quiet --ignore-missing SHA256SUMS.txt ) \
  || { echo "[build_cuda] ERROR: vendored source hash mismatch; refusing to build." >&2; exit 4; }

cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCUDAToolkit_ROOT="$CUDA_ROOT" \
  -DCMAKE_CUDA_COMPILER="$CUDA_ROOT/bin/nvcc"

cmake --build "$BUILD" --parallel

echo "[build_cuda] DONE. Binary: $BUILD/bin/rckangaroo"
echo "[build_cuda] The patched binary emits keys ONLY to --candidate-fd; always"
echo "[build_cuda] run it through rckangaroo/adapter/rck_adapter.py."
