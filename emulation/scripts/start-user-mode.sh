#!/bin/bash
# start-user-mode.sh — Run a single binary via QEMU user-mode
#
# Usage: start-user-mode.sh <arch> <rootfs_path> <binary_path> [args...]
#
# Uses QEMU's -L flag to set the library search root (no chroot needed),
# so the rootfs can be mounted read-only.

set -e

ARCH="$1"
ROOTFS="$2"
BINARY="$3"
shift 3

if [ -z "$ARCH" ] || [ -z "$ROOTFS" ] || [ -z "$BINARY" ]; then
    echo "Usage: start-user-mode.sh <arch> <rootfs_path> <binary_path> [args...]" >&2
    exit 1
fi

# Map architecture to QEMU binary name
case "$ARCH" in
    arm|armhf|armel)
        QEMU_BIN="qemu-arm-static"
        ;;
    aarch64|arm64)
        QEMU_BIN="qemu-aarch64-static"
        ;;
    mips|mipsbe)
        QEMU_BIN="qemu-mips-static"
        ;;
    mipsel|mipsle)
        QEMU_BIN="qemu-mipsel-static"
        ;;
    x86|i386|i686)
        QEMU_BIN="qemu-i386-static"
        ;;
    x86_64|amd64)
        QEMU_BIN="qemu-x86_64-static"
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

QEMU_PATH=$(which "$QEMU_BIN" 2>/dev/null)
if [ -z "$QEMU_PATH" ]; then
    echo "QEMU binary not found: $QEMU_BIN" >&2
    exit 1
fi

# Use QEMU's -L flag to set library root prefix (works with read-only rootfs).
# The binary path is relative to the rootfs, so prepend rootfs path.
FULL_BINARY="${ROOTFS}/${BINARY#/}"

if [ ! -f "$FULL_BINARY" ]; then
    echo "Binary not found: $FULL_BINARY" >&2
    exit 1
fi

exec "$QEMU_PATH" -L "$ROOTFS" "$FULL_BINARY" "$@"
