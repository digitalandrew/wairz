# Stage 1: Cross-compile LD_PRELOAD stub libraries for all architectures
FROM debian:bookworm-slim AS stub-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mipsel-linux-gnu \
    gcc-mips-linux-gnu \
    gcc-arm-linux-gnueabi \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

COPY stubs/ /src/stubs/

# Compile fake_mtd for each architecture.
# -nostdlib: no libc dependency (works in any firmware environment)
# -fPIC -shared: build as position-independent shared library
# -Wl,--hash-style=sysv: compatible with older/embedded linkers
RUN mkdir -p /out/stubs && \
    mipsel-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
        -o /out/stubs/fake_mtd_mipsel.so /src/stubs/fake_mtd.c && \
    mips-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
        -o /out/stubs/fake_mtd_mips.so /src/stubs/fake_mtd.c && \
    arm-linux-gnueabi-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
        -o /out/stubs/fake_mtd_arm.so /src/stubs/fake_mtd.c && \
    aarch64-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
        -o /out/stubs/fake_mtd_aarch64.so /src/stubs/fake_mtd.c

# Stage 2: Runtime image
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

# Copy pre-compiled stub libraries from builder stage
COPY --from=stub-builder /out/stubs/ /opt/stubs/

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
