#!/bin/bash
# start-system-mode.sh — Boot firmware via QEMU system-mode
#
# Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]
#
# This script boots a full system-mode QEMU instance with the firmware
# filesystem as the root. Serial console is exposed via socat on a Unix socket.

ARCH="$1"
ROOTFS="$2"
KERNEL="$3"
PORT_FORWARDS="$4"  # comma-separated host:guest pairs, e.g., "8080:80,2222:22"

LOG="/tmp/qemu-system.log"
SERIAL_SOCK="/tmp/qemu-serial.sock"
ROOTFS_IMG="/tmp/rootfs.ext4"

# Always create the log file immediately so diagnostics are available
exec > >(tee -a "$LOG") 2>&1

echo "=== QEMU System-Mode Start ==="
echo "Time: $(date -u 2>/dev/null || echo unknown)"
echo "Arch: $ARCH"
echo "Rootfs: $ROOTFS"
echo "Kernel: $KERNEL"
echo "Port forwards: $PORT_FORWARDS"

if [ -z "$ARCH" ] || [ -z "$ROOTFS" ] || [ -z "$KERNEL" ]; then
    echo "ERROR: Usage: start-system-mode.sh <arch> <rootfs_path> <kernel_path> [port_forwards]"
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: Kernel not found: $KERNEL"
    echo "System-mode emulation requires a pre-built kernel for the target architecture."
    echo "Upload a kernel via the Kernel Manager or place one in emulation/kernels/."
    exit 1
fi

if [ ! -d "$ROOTFS" ]; then
    echo "ERROR: Rootfs directory not found: $ROOTFS"
    exit 1
fi

echo "Kernel file size: $(wc -c < "$KERNEL") bytes"

# Clean up stale files from previous runs
rm -f "$SERIAL_SOCK" "$ROOTFS_IMG"

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

# Create a temporary ext4 image from the rootfs
echo "Creating ext4 rootfs image (256 MB)..."
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=256 2>/dev/null
if ! mkfs.ext4 -q -d "$ROOTFS" "$ROOTFS_IMG" 2>&1; then
    echo "WARNING: mkfs.ext4 -d failed, trying without directory copy..."
    mkfs.ext4 -q "$ROOTFS_IMG" 2>&1 || true
fi
echo "Rootfs image created: $(wc -c < "$ROOTFS_IMG") bytes"

# Select QEMU binary and machine type
case "$ARCH" in
    arm|armhf|armel)
        QEMU_BIN="qemu-system-arm"
        MACHINE="versatilepb"
        CONSOLE="ttyAMA0"
        ;;
    aarch64|arm64)
        QEMU_BIN="qemu-system-aarch64"
        MACHINE="virt"
        CONSOLE="ttyAMA0"
        ;;
    mips|mipsbe)
        QEMU_BIN="qemu-system-mips"
        MACHINE="malta"
        CONSOLE="ttyS0"
        ;;
    mipsel|mipsle)
        QEMU_BIN="qemu-system-mipsel"
        MACHINE="malta"
        CONSOLE="ttyS0"
        ;;
    x86|i386|i686)
        QEMU_BIN="qemu-system-i386"
        MACHINE="pc"
        CONSOLE="ttyS0"
        ;;
    x86_64|amd64)
        QEMU_BIN="qemu-system-x86_64"
        MACHINE="pc"
        CONSOLE="ttyS0"
        ;;
    *)
        echo "ERROR: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Verify QEMU binary exists
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "ERROR: $QEMU_BIN not found in PATH"
    exit 1
fi

echo "Starting: $QEMU_BIN -M $MACHINE"
echo "Serial console: $SERIAL_SOCK"
echo "Kernel append: root=/dev/sda rw console=$CONSOLE"

# Launch QEMU
# -nodefaults: suppress audio/USB/etc warnings
# -no-reboot: exit instead of rebooting (prevents infinite loops)
exec "$QEMU_BIN" \
    -M "$MACHINE" \
    -m 256 \
    -nographic \
    -nodefaults \
    -no-reboot \
    -serial "unix:${SERIAL_SOCK},server,nowait" \
    -monitor none \
    -kernel "$KERNEL" \
    -drive "file=$ROOTFS_IMG,format=raw" \
    -append "root=/dev/sda rw console=$CONSOLE panic=1" \
    $NET_ARGS
