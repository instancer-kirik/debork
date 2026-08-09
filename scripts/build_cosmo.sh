#!/bin/bash
# debork Cosmopolitan C Build Script
# Produces a portable APE binary (runs on Linux x86-64/aarch64, macOS, Windows)

set -e

COSMO_VERSION="3.3.2"
COSMO_TARBALL="cosmocc-${COSMO_VERSION}.zip"
COSMO_URL="https://github.com/jart/cosmopolitan/releases/download/${COSMO_VERSION}/${COSMO_TARBALL}"
COSMO_DIR="cosmocc"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_FILE="${REPO_ROOT}/src/c/debork_cute.c"
BUILD_DIR="${REPO_ROOT}/build"
OUTPUT_NAME="debork"

# ── helpers ────────────────────────────────────────────────────────────────────
info()    { echo -e "\033[0;34m[INFO]\033[0m $*"; }
ok()      { echo -e "\033[0;32m[OK]\033[0m $*"; }
warn()    { echo -e "\033[1;33m[WARN]\033[0m $*"; }
die()     { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; exit 1; }

# ── toolchain setup ────────────────────────────────────────────────────────────
setup_cosmocc() {
    local cosmo_home="${BUILD_DIR}/${COSMO_DIR}"
    local cosmocc="${cosmo_home}/bin/cosmocc"

    if [ -x "$cosmocc" ]; then
        info "cosmocc already present at ${cosmocc}"
        echo "$cosmocc"
        return
    fi

    info "Downloading cosmocc ${COSMO_VERSION}..."
    mkdir -p "$BUILD_DIR"

    if command -v curl &>/dev/null; then
        curl -L --progress-bar "$COSMO_URL" -o "${BUILD_DIR}/${COSMO_TARBALL}"
    elif command -v wget &>/dev/null; then
        wget -q --show-progress "$COSMO_URL" -O "${BUILD_DIR}/${COSMO_TARBALL}"
    else
        die "Neither curl nor wget found. Install one and retry."
    fi

    info "Extracting cosmocc..."
    mkdir -p "$cosmo_home"
    unzip -q "${BUILD_DIR}/${COSMO_TARBALL}" -d "$cosmo_home"
    chmod +x "${cosmo_home}/bin/"*

    ok "cosmocc ready at ${cosmocc}"
    echo "$cosmocc"
}

# ── build ──────────────────────────────────────────────────────────────────────
build_cosmo() {
    local cosmocc
    cosmocc="$(setup_cosmocc)"
    mkdir -p "$BUILD_DIR"

    info "Compiling ${SOURCE_FILE} with cosmocc..."
    "$cosmocc" \
        -O2 \
        -o "${BUILD_DIR}/${OUTPUT_NAME}.com" \
        "$SOURCE_FILE" \
        -lm

    ok "APE binary: ${BUILD_DIR}/${OUTPUT_NAME}.com"
    ls -lh "${BUILD_DIR}/${OUTPUT_NAME}.com"
}

build_static() {
    info "Building static Linux binary (musl)..."
    mkdir -p "$BUILD_DIR"

    local cc
    if command -v musl-gcc &>/dev/null; then
        cc="musl-gcc"
    elif command -v gcc &>/dev/null; then
        warn "musl-gcc not found, falling back to gcc -static (glibc static is fragile)"
        cc="gcc"
    else
        die "No C compiler found."
    fi

    "$cc" -O2 -static \
        -o "${BUILD_DIR}/${OUTPUT_NAME}-static" \
        "$SOURCE_FILE" \
        -lm

    ok "Static binary: ${BUILD_DIR}/${OUTPUT_NAME}-static"
    ls -lh "${BUILD_DIR}/${OUTPUT_NAME}-static"
}

# ── package ────────────────────────────────────────────────────────────────────
create_package() {
    info "Creating distribution package..."
    local pkg_dir="${BUILD_DIR}/debork-portable"
    mkdir -p "$pkg_dir"

    for bin in "${BUILD_DIR}/${OUTPUT_NAME}.com" "${BUILD_DIR}/${OUTPUT_NAME}-static" "${BUILD_DIR}/${OUTPUT_NAME}"; do
        if [ -f "$bin" ]; then
            cp "$bin" "$pkg_dir/"
            chmod +x "$pkg_dir/$(basename "$bin")"
        fi
    done

    [ "$(ls -A "$pkg_dir")" ] || die "No binary found to package. Build first."

    tar -czf "${BUILD_DIR}/debork-portable.tar.gz" -C "$BUILD_DIR" "debork-portable/"
    ok "Package: ${BUILD_DIR}/debork-portable.tar.gz"
}

clean() {
    info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    ok "Clean complete"
}

# ── main ───────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
  cosmo    Build portable APE binary with cosmocc (default)
  static   Build static Linux binary (needs musl-gcc for reliability)
  package  Bundle built binary into a tar.gz
  clean    Remove build directory
  help     Show this help
EOF
}

case "${1:-cosmo}" in
    cosmo)   build_cosmo ;;
    static)  build_static ;;
    package) create_package ;;
    clean)   clean ;;
    help|--help|-h) usage ;;
    *) die "Unknown command: $1. Run '$0 help' for usage." ;;
esac
