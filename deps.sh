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

# ---- Helpers ----
info()  { echo -e "\033[1;34m[deps]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[deps]\033[0m $*"; }
err()   { echo -e "\033[1;31m[deps]\033[0m $*" >&2; }

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        err "Required tool not found: $1"
        err "Install with: apt-get install -y $2"
        exit 1
    fi
}

# ---- Clone or update a dependency ----
clone_or_update() {
    local name="$1" repo="$2" commit="$3" dir="${DEPS_DIR}/${name}"

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
}

# ---- Build BoringSSL ----
build_boringssl() {
    local dir="${DEPS_DIR}/boringssl"
    if [ -f "${dir}/build/libssl.a" ] && [ -f "${dir}/build/libcrypto.a" ]; then
        ok "BoringSSL: already built"
        return
    fi

    check_tool cmake cmake
    check_tool go golang
    check_tool ninja ninja-build

    info "BoringSSL: configuring..."
    cmake -B "${dir}/build" -S "${dir}" \
        -GNinja \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_BUILD_TYPE=Release

    info "BoringSSL: building (this takes a while)..."
    ninja -C "${dir}/build" ssl crypto

    ok "BoringSSL: built"
}

# ---- Build nghttp3 ----
build_nghttp3() {
    local dir="${DEPS_DIR}/nghttp3"
    if [ -f "${dir}/build/lib/libnghttp3.a" ]; then
        ok "nghttp3: already built"
        return
    fi

    check_tool autoreconf autoconf
    check_tool automake automake
    check_tool libtool libtool
    check_tool pkg-config pkg-config

    info "nghttp3: autoreconf..."
    cd "$dir"
    autoreconf -fi

    info "nghttp3: configuring..."
    ./configure --prefix="${dir}/build" --enable-lib-only

    info "nghttp3: building..."
    make -j"$(nproc)"
    make install

    ok "nghttp3: built"
}

# ---- Build ngtcp2 ----
build_ngtcp2() {
    local dir="${DEPS_DIR}/ngtcp2"
    local bssl_dir="${DEPS_DIR}/boringssl"
    local nh3_dir="${DEPS_DIR}/nghttp3"

    if [ -f "${dir}/lib/.libs/libngtcp2.a" ] && \
       [ -f "${dir}/crypto/boringssl/libngtcp2_crypto_boringssl.a" ]; then
        ok "ngtcp2: already built"
        return
    fi

    check_tool autoreconf autoconf

    info "ngtcp2: autoreconf..."
    cd "$dir"
    autoreconf -fi

    info "ngtcp2: configuring with BoringSSL..."
    ./configure \
        PKG_CONFIG_PATH="${nh3_dir}/build/lib/pkgconfig" \
        BORINGSSL_LIBS="-L${bssl_dir}/build -lssl -lcrypto" \
        BORINGSSL_CFLAGS="-I${bssl_dir}/include" \
        --with-boringssl

    info "ngtcp2: building..."
    make -j"$(nproc)"

    ok "ngtcp2: built"
}

# ---- Main commands ----
cmd_fetch() {
    info "Fetching all dependencies..."
    clone_or_update "boringssl" "$BORINGSSL_REPO" "$BORINGSSL_COMMIT"
    clone_or_update "ngtcp2"    "$NGTCP2_REPO"    "$NGTCP2_COMMIT"
    clone_or_update "nghttp3"   "$NGHTTP3_REPO"   "$NGHTTP3_REF"
    ok "All dependencies fetched"
}

cmd_build() {
    info "Building all dependencies..."
    build_boringssl
    build_nghttp3
    build_ngtcp2
    ok "All dependencies built"
}

cmd_all() {
    cmd_fetch
    cmd_build
}

cmd_status() {
    echo "=== Dependency Status ==="
    echo ""
    for dep in boringssl ngtcp2 nghttp3; do
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
    for f in \
        "boringssl/build/libssl.a" \
        "boringssl/build/libcrypto.a" \
        "nghttp3/build/lib/libnghttp3.a" \
        "ngtcp2/lib/.libs/libngtcp2.a" \
        "ngtcp2/crypto/boringssl/libngtcp2_crypto_boringssl.a"; do
        if [ -f "${DEPS_DIR}/${f}" ]; then
            printf "  \033[32m✓\033[0m %s\n" "$f"
        else
            printf "  \033[31m✗\033[0m %s\n" "$f"
        fi
    done
}

cmd_clean() {
    info "Cleaning build artifacts..."
    rm -rf "${DEPS_DIR}/boringssl/build"
    rm -rf "${DEPS_DIR}/nghttp3/build"
    cd "${DEPS_DIR}/ngtcp2" 2>/dev/null && make distclean 2>/dev/null || true
    ok "Cleaned"
}

# ---- Usage ----
usage() {
    cat <<EOF
usque-a dependency manager

Usage: $(basename "$0") <command>

Commands:
  fetch     Clone/update dependencies at pinned commits
  build     Build all dependencies (BoringSSL → nghttp3 → ngtcp2)
  all       fetch + build
  status    Show dependency and build status
  clean     Remove build artifacts

Pinned versions:
  BoringSSL  ${BORINGSSL_COMMIT:0:12}  ${BORINGSSL_REPO}
  ngtcp2     ${NGTCP2_COMMIT:0:12}  ${NGTCP2_REPO}
  nghttp3    ${NGHTTP3_REF}          ${NGHTTP3_REPO} (fork)
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
