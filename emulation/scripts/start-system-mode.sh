#!/bin/bash
# start-system-mode.sh — Boot firmware via QEMU system-mode
#
# Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]
#
# This script boots a full system-mode QEMU instance with the firmware
# filesystem as the root. Serial console is exposed via socat on a Unix socket.

set -e

ARCH="$1"
ROOTFS="$2"
KERNEL="$3"
PORT_FORWARDS="$4"  # comma-separated host:guest pairs, e.g., "8080:80,2222:22"

if [ -z "$ARCH" ] || [ -z "$ROOTFS" ] || [ -z "$KERNEL" ]; then
    echo "Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]" >&2
    exit 1
fi

SERIAL_SOCK="/tmp/qemu-serial.sock"

# Build common QEMU args
QEMU_ARGS="-nographic -serial unix:${SERIAL_SOCK},server,nowait"
QEMU_ARGS="$QEMU_ARGS -m 256"

# Build port forwarding for user-mode networking
NET_ARGS="-net nic -net user"
if [ -n "$PORT_FORWARDS" ]; then
    IFS=',' read -ra PAIRS <<< "$PORT_FORWARDS"
    for pair in "${PAIRS[@]}"; do
        host_port="${pair%%:*}"
        guest_port="${pair##*:}"
        NET_ARGS="$NET_ARGS,hostfwd=tcp::${host_port}-:${guest_port}"
    done
fi
QEMU_ARGS="$QEMU_ARGS $NET_ARGS"

# Create a temporary ext4 image from the rootfs
ROOTFS_IMG="/tmp/rootfs.ext4"
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=256 2>/dev/null
mkfs.ext4 -q -d "$ROOTFS" "$ROOTFS_IMG"

# Select QEMU binary and machine type
case "$ARCH" in
    arm|armhf|armel)
        QEMU_BIN="qemu-system-arm"
        QEMU_ARGS="$QEMU_ARGS -M versatilepb"
        QEMU_ARGS="$QEMU_ARGS -kernel $KERNEL"
        QEMU_ARGS="$QEMU_ARGS -drive file=$ROOTFS_IMG,format=raw"
        QEMU_ARGS="$QEMU_ARGS -append \"root=/dev/sda rw console=ttyAMA0\""
        ;;
    mips|mipsbe)
        QEMU_BIN="qemu-system-mips"
        QEMU_ARGS="$QEMU_ARGS -M malta"
        QEMU_ARGS="$QEMU_ARGS -kernel $KERNEL"
        QEMU_ARGS="$QEMU_ARGS -drive file=$ROOTFS_IMG,format=raw"
        QEMU_ARGS="$QEMU_ARGS -append \"root=/dev/sda rw console=ttyS0\""
        ;;
    mipsel|mipsle)
        QEMU_BIN="qemu-system-mipsel"
        QEMU_ARGS="$QEMU_ARGS -M malta"
        QEMU_ARGS="$QEMU_ARGS -kernel $KERNEL"
        QEMU_ARGS="$QEMU_ARGS -drive file=$ROOTFS_IMG,format=raw"
        QEMU_ARGS="$QEMU_ARGS -append \"root=/dev/sda rw console=ttyS0\""
        ;;
    x86|i386|i686|x86_64|amd64)
        QEMU_BIN="qemu-system-x86_64"
        QEMU_ARGS="$QEMU_ARGS -M pc"
        QEMU_ARGS="$QEMU_ARGS -kernel $KERNEL"
        QEMU_ARGS="$QEMU_ARGS -drive file=$ROOTFS_IMG,format=raw"
        QEMU_ARGS="$QEMU_ARGS -append \"root=/dev/sda rw console=ttyS0\""
        ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

# Launch QEMU
echo "Starting QEMU system-mode: $QEMU_BIN"
echo "Serial console: $SERIAL_SOCK"
eval exec "$QEMU_BIN" $QEMU_ARGS
