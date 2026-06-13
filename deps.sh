#!/bin/bash
# usque-a dependency management script
# Pins exact commits for reproducible builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_DIR="${SCRIPT_DIR}/deps"

# ---- Pinned dependency commits ----
BORINGSSL_REPO="https://boringssl.googlesource.com/boringssl"
BORINGSSL_COMMIT="ef4f3c2197f90c96a44716aedaac55a10cb4e479"

NGTCP2_REPO="https://github.com/ngtcp2/ngtcp2"
NGTCP2_COMMIT="9496b2da0d968f0ab1d5da689effe4d28eb6ead4"

NGHTTP3_REPO="https://github.com/justinwoo280/nghttp3"
NGHTTP3_REF="origin/main"

LIBUV_REPO="https://github.com/libuv/libuv"
LIBUV_TAG="v1.49.2"

# ---- Helpers ----
info()  { echo -e "\033[1;34m[deps]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[deps]\033[0m $*"; }
err()   { echo -e "\033[1;31m[deps]\033[0m $*" >&2; }

get_nproc() {
    if command -v nproc &>/dev/null; then nproc
    elif [ -n "${NUMBER_OF_PROCESSORS:-}" ]; then echo "$NUMBER_OF_PROCESSORS"
    elif command -v sysctl &>/dev/null; then sysctl -n hw.ncpu
    else echo 4; fi
}

# Detect platform
is_windows() {
    [[ "${OS:-}" == "Windows_NT" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]
}

# Static library extension
static_ext() {
    if is_windows; then echo "lib"; else echo "a"; fi
}

# CMake generator: Ninja everywhere (single-config, avoids MSVC Debug/Release subdirs)
cmake_gen() {
    if command -v ninja &>/dev/null; then
        echo "-GNinja"
    fi
}

# Convert MSYS path to Windows-native path with forward slashes (D:/a/...)
# CMake requires forward slashes; backslashes are treated as escape chars.
to_winpath() {
    if is_windows && command -v cygpath &>/dev/null; then
        cygpath -m "$1"
    elif is_windows; then
        # Manual conversion: /d/foo/bar → D:/foo/bar
        local p="$1"
        local drive="${p:1:1}"
        local rest="${p:2}"
        echo "${drive^^}:${rest}"
    else
        echo "$1"
    fi
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        err "Required tool not found: $1"
        err "Install with: apt-get install -y $2"
        exit 1
    fi
}

# Find a static library file, checking both .a and .lib
find_static_lib() {
    local dir="$1" base="$2"
    if [ -f "${dir}/${base}.a" ]; then
        echo "${dir}/${base}.a"
    elif [ -f "${dir}/${base}.lib" ]; then
        echo "${dir}/${base}.lib"
    else
        return 1
    fi
}

# ---- Clone or update a dependency ----
clone_or_update() {
    local name="$1" repo="$2" commit="$3"
    local dir="${DEPS_DIR}/${name}"

    if [ -d "$dir/.git" ]; then
        info "${name}: updating..."
        git -C "$dir" fetch --all --quiet
    else
        info "${name}: cloning ${repo}..."
        mkdir -p "$DEPS_DIR"
        git clone --quiet "$repo" "$dir"
    fi

    info "${name}: checking out ${commit:0:12}..."
    git -C "$dir" checkout --quiet "$commit"

    if [ -f "$dir/.gitmodules" ]; then
        info "${name}: initializing submodules..."
        git -C "$dir" submodule update --init --quiet
    fi
}

# ---- Build BoringSSL ----
build_boringssl() {
    local dir="${DEPS_DIR}/boringssl"
    if find_static_lib "${dir}/build" "libssl" &>/dev/null && \
       find_static_lib "${dir}/build" "libcrypto" &>/dev/null; then
        ok "BoringSSL: already built"
        return
    fi
    # Also check Windows naming: ssl.lib / crypto.lib
    if find_static_lib "${dir}/build" "ssl" &>/dev/null && \
       find_static_lib "${dir}/build" "crypto" &>/dev/null; then
        ok "BoringSSL: already built"
        return
    fi

    check_tool cmake cmake
    check_tool go golang

    info "BoringSSL: configuring..."
    cmake -B "${dir}/build" -S "${dir}" \
        $(cmake_gen) \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_BUILD_TYPE=Release \
        $(suppress_warnings_flag)

    info "BoringSSL: building (this takes a while)..."
    cmake --build "${dir}/build" -j"$(get_nproc)" --target ssl crypto

    ok "BoringSSL: built"
}

# ---- Build nghttp3 ----
build_nghttp3() {
    local dir="${DEPS_DIR}/nghttp3"
    if find_static_lib "${dir}/build/lib" "libnghttp3" &>/dev/null || \
       find_static_lib "${dir}/build/lib" "nghttp3" &>/dev/null; then
        ok "nghttp3: already built"
        return
    fi

    check_tool cmake cmake

    info "nghttp3: configuring..."
    cmake -B "${dir}/build" -S "${dir}" \
        $(cmake_gen) \
        -DENABLE_SHARED_LIB=OFF \
        -DENABLE_STATIC_LIB=ON \
        -DENABLE_LIB_ONLY=ON \
        -DBUILD_TESTING=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        $(suppress_warnings_flag)

    info "nghttp3: building..."
    cmake --build "${dir}/build" -j"$(get_nproc)"

    ok "nghttp3: built"
}

# ---- Build ngtcp2 ----
build_ngtcp2() {
    local dir="${DEPS_DIR}/ngtcp2"
    local bssl_dir="${DEPS_DIR}/boringssl"

    if find_static_lib "${dir}/build/lib" "libngtcp2" &>/dev/null || \
       find_static_lib "${dir}/build/lib" "ngtcp2" &>/dev/null; then
        ok "ngtcp2: already built"
        return
    fi

    check_tool cmake cmake

    # Find BoringSSL libraries (platform-aware)
    local ssl_lib crypto_lib
    ssl_lib=$(find_static_lib "${bssl_dir}/build" "libssl" 2>/dev/null || \
              find_static_lib "${bssl_dir}/build" "ssl")
    crypto_lib=$(find_static_lib "${bssl_dir}/build" "libcrypto" 2>/dev/null || \
                 find_static_lib "${bssl_dir}/build" "crypto")

    # Convert paths for MSVC compatibility
    local bssl_inc ssl_lib_w crypto_lib_w
    bssl_inc="$(to_winpath "${bssl_dir}/include")"
    ssl_lib_w="$(to_winpath "${ssl_lib}")"
    crypto_lib_w="$(to_winpath "${crypto_lib}")"

    info "ngtcp2: configuring with BoringSSL..."
    info "ngtcp2: include=${bssl_inc}"
    info "ngtcp2: ssl_lib=${ssl_lib_w}"
    info "ngtcp2: crypto_lib=${crypto_lib_w}"

    cmake -B "${dir}/build" -S "${dir}" \
        $(cmake_gen) \
        -DENABLE_SHARED_LIB=OFF \
        -DENABLE_STATIC_LIB=ON \
        -DENABLE_LIB_ONLY=ON \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_BORINGSSL=ON \
        -DBORINGSSL_INCLUDE_DIR="${bssl_inc}" \
        -DBORINGSSL_LIBRARIES="${ssl_lib_w};${crypto_lib_w}" \
        -DBUILD_TESTING=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        $(suppress_warnings_flag)

    info "ngtcp2: building..."
    cmake --build "${dir}/build" -j"$(get_nproc)"

    ok "ngtcp2: built"
}

# ---- Build libuv ----
# Compiler warning suppression for third-party dependency builds
suppress_warnings_flag() {
    if is_windows; then
        echo "-DCMAKE_C_FLAGS=/W0 -DCMAKE_CXX_FLAGS=/W0"
    else
        echo "-DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w"
    fi
}

build_libuv() {
    local dir="${DEPS_DIR}/libuv"
    if find_static_lib "${dir}/build" "libuv_a" &>/dev/null || \
       find_static_lib "${dir}/build" "libuv" &>/dev/null || \
       find_static_lib "${dir}/build" "uv_a" &>/dev/null; then
        ok "libuv: already built"
        return
    fi

    check_tool cmake cmake

    info "libuv: configuring..."
    cmake -B "${dir}/build" -S "${dir}" \
        $(cmake_gen) \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBUV_BUILD_TESTS=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        $(suppress_warnings_flag)

    info "libuv: building..."
    cmake --build "${dir}/build" -j"$(get_nproc)"

    ok "libuv: built"
}

# ---- Main commands ----
cmd_fetch() {
    info "Fetching all dependencies..."
    clone_or_update "boringssl" "$BORINGSSL_REPO" "$BORINGSSL_COMMIT"
    clone_or_update "ngtcp2"    "$NGTCP2_REPO"    "$NGTCP2_COMMIT"
    clone_or_update "nghttp3"   "$NGHTTP3_REPO"   "$NGHTTP3_REF"
    clone_or_update "libuv"     "$LIBUV_REPO"     "$LIBUV_TAG"
    ok "All dependencies fetched"
}

cmd_build() {
    info "Building all dependencies..."
    build_boringssl
    build_nghttp3
    build_ngtcp2
    build_libuv
    ok "All dependencies built"
}

cmd_all() {
    cmd_fetch
    cmd_build
}

cmd_status() {
    echo "=== Dependency Status ==="
    echo ""
    for dep in boringssl ngtcp2 nghttp3 libuv; do
        local dir="${DEPS_DIR}/${dep}"
        if [ -d "$dir/.git" ]; then
            local hash
            hash=$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo "unknown")
            printf "  %-12s %s\n" "${dep}" "${hash}"
        else
            printf "  %-12s (not cloned)\n" "${dep}"
        fi
    done
    echo ""
    echo "=== Build Artifacts ==="
    echo ""
    local ext
    ext=$(static_ext)
    for f in \
        "boringssl/build/ssl.${ext}" \
        "boringssl/build/libssl.${ext}" \
        "boringssl/build/crypto.${ext}" \
        "boringssl/build/libcrypto.${ext}" \
        "nghttp3/build/lib/nghttp3.${ext}" \
        "nghttp3/build/lib/libnghttp3.${ext}" \
        "ngtcp2/build/lib/ngtcp2.${ext}" \
        "ngtcp2/build/lib/libngtcp2.${ext}" \
        "libuv/build/uv_a.${ext}" \
        "libuv/build/libuv_a.${ext}" \
        "libuv/build/libuv.${ext}"; do
        if [ -f "${DEPS_DIR}/${f}" ]; then
            printf "  \033[32m✓\033[0m %s\n" "$f"
        fi
    done
}

cmd_clean() {
    info "Cleaning build artifacts..."
    rm -rf "${DEPS_DIR}/boringssl/build"
    rm -rf "${DEPS_DIR}/nghttp3/build"
    rm -rf "${DEPS_DIR}/ngtcp2/build"
    rm -rf "${DEPS_DIR}/libuv/build"
    ok "Cleaned"
}

# ---- Usage ----
usage() {
    cat <<EOF
usque-a dependency manager

Usage: $(basename "$0") <command>

Commands:
  fetch     Clone/update dependencies at pinned commits
  build     Build all dependencies (BoringSSL → nghttp3 → ngtcp2 → libuv)
  all       fetch + build
  status    Show dependency and build status
  clean     Remove build artifacts

Pinned versions:
  BoringSSL  ${BORINGSSL_COMMIT:0:12}  ${BORINGSSL_REPO}
  ngtcp2     ${NGTCP2_COMMIT:0:12}  ${NGTCP2_REPO}
  nghttp3    ${NGHTTP3_REF}          ${NGHTTP3_REPO} (fork)
  libuv      ${LIBUV_TAG}            ${LIBUV_REPO}
EOF
}

case "${1:-}" in
    fetch)  cmd_fetch  ;;
    build)  cmd_build  ;;
    all)    cmd_all    ;;
    status) cmd_status ;;
    clean)  cmd_clean  ;;
    *)      usage      ;;
esac
