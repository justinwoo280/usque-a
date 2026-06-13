#!/bin/bash
# usque-a build script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_DIR="${SCRIPT_DIR}/deps"
BUILD_DIR="${SCRIPT_DIR}/build"

info()  { echo -e "\033[1;34m[build]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[build]\033[0m $*"; }
err()   { echo -e "\033[1;31m[build]\033[0m $*" >&2; }

get_nproc() {
    if command -v nproc &>/dev/null; then nproc
    elif [ -n "${NUMBER_OF_PROCESSORS:-}" ]; then echo "$NUMBER_OF_PROCESSORS"
    elif command -v sysctl &>/dev/null; then sysctl -n hw.ncpu
    else echo 4; fi
}

# Verify deps are built
check_deps() {
    local missing=0
    for f in \
        "boringssl/build/libssl.a" \
        "boringssl/build/libcrypto.a" \
        "nghttp3/build/lib/libnghttp3.a" \
        "ngtcp2/build/lib/libngtcp2.a" \
        "ngtcp2/build/crypto/boringssl/libngtcp2_crypto_boringssl.a"; do
        if [ ! -f "${DEPS_DIR}/${f}" ]; then
            err "Missing: ${DEPS_DIR}/${f}"
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        err "Run './deps.sh all' first to build dependencies"
        exit 1
    fi
}

cmd_build() {
    check_deps

    local build_type="${BUILD_TYPE:-Release}"
    local shared_libs="OFF"
    local jobs="${JOBS:-$(get_nproc)}"

    info "Build type: ${build_type}"
    info "Parallel jobs: ${jobs}"

    cmake -B "${BUILD_DIR}" -S "${SCRIPT_DIR}" \
        -DBUILD_SHARED_LIBS="${shared_libs}" \
        -DCMAKE_BUILD_TYPE="${build_type}" \
        -DBORINGSSL_DIR="${DEPS_DIR}/boringssl" \
        -DNGTCP2_DIR="${DEPS_DIR}/ngtcp2" \
        -DNGHTTP3_DIR="${DEPS_DIR}/nghttp3"

    cmake --build "${BUILD_DIR}" -- -j"${jobs}"

    ok "Build complete: ${BUILD_DIR}/src/usque-a-cli"
}

cmd_test() {
    if [ ! -d "${BUILD_DIR}" ]; then
        err "Build directory not found. Run './build.sh build' first."
        exit 1
    fi

    info "Running tests..."
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
    ok "All tests passed"
}

cmd_clean() {
    info "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
    ok "Cleaned"
}

cmd_install() {
    check_deps
    local prefix="${PREFIX:-/usr/local}"
    info "Installing to ${prefix}..."
    cmake --install "${BUILD_DIR}" --prefix "${prefix}"
    ok "Installed"
}

cmd_release() {
    info "Building release..."
    BUILD_TYPE=Release cmd_build

    # Detect binary name (Windows uses .exe)
    local bin="${BUILD_DIR}/src/usque-a-cli"
    if [ -f "${bin}.exe" ]; then
        bin="${bin}.exe"
    fi

    info "Stripping binary..."
    local stripped="${bin}.stripped"
    if command -v strip &>/dev/null; then
        strip -o "$stripped" "$bin" 2>/dev/null || cp "$bin" "$stripped"
    else
        cp "$bin" "$stripped"
    fi

    local size
    size=$(ls -lh "$stripped" | awk '{print $5}')
    ok "Release binary: ${stripped} (${size})"
}

usage() {
    cat <<EOF
usque-a build system

Usage: $(basename "$0") <command>

Commands:
  build     Configure and build the project (default: Release)
  test      Run all tests
  release   Build + strip for deployment
  clean     Remove build directory
  install   Install to PREFIX (default: /usr/local)

Environment variables:
  BUILD_TYPE    CMake build type (Release, Debug, RelWithDebInfo)
  JOBS          Parallel build jobs (default: nproc)
  PREFIX        Install prefix (default: /usr/local)

Quick start:
  ./deps.sh all       # Fetch and build dependencies
  ./build.sh build    # Build the project
  ./build.sh test     # Run tests
EOF
}

case "${1:-build}" in
    build)   cmd_build   ;;
    test)    cmd_test    ;;
    release) cmd_release ;;
    clean)   cmd_clean   ;;
    install) cmd_install ;;
    *)       usage       ;;
esac
