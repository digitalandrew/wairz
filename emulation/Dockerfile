FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    qemu-system-arm \
    qemu-system-mips \
    qemu-system-x86 \
    busybox-static \
    socat \
    iproute2 \
    bridge-utils \
    e2fsprogs \
    kpartx \
    xxd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy helper scripts
COPY scripts/ /opt/scripts/
RUN chmod +x /opt/scripts/*.sh

# Create non-root user for emulation
RUN useradd -m -s /bin/bash emulator

# Kernels directory (mounted from host or baked in)
RUN mkdir -p /opt/kernels /data/firmware

# Default working directory
WORKDIR /opt

# Keep container alive — managed by Docker SDK from the backend
CMD ["sleep", "infinity"]
