# =============================================================================
# AFL++ Fuzzing Container for Wairz
#
# Multi-stage build:
#   Stage 1 — Build AFL++ from source with QEMU mode for ARM, MIPS, MIPSel
#   Stage 2 — Lean runtime image with AFL++ binaries + crash triage tools
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build AFL++ with QEMU mode for cross-architecture firmware fuzzing
# ---------------------------------------------------------------------------
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y \
    git make gcc g++ python3 python3-dev python3-venv \
    gcc-12-plugin-dev \
    libtool libtool-bin automake bison flex \
    libglib2.0-dev libpixman-1-dev \
    ninja-build meson pkg-config wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone AFL++ stable branch
ARG AFLPP_VERSION=v4.21c
RUN git clone --depth 1 --branch stable https://github.com/AFLplusplus/AFLplusplus.git /aflpp

WORKDIR /aflpp

# Build core AFL++ tools (source-only = no LLVM/clang dependency)
RUN make -j$(nproc) source-only && make install

# Build QEMU mode for each target architecture needed for firmware fuzzing.
# Each invocation downloads QEMU source (cached after first), patches it,
# and produces an afl-qemu-trace binary for that guest architecture.

# ARM (32-bit) — most common embedded firmware arch
RUN cd qemu_mode && CPU_TARGET=arm ./build_qemu_support.sh \
    && cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-arm

# MIPS big-endian
RUN cd qemu_mode && CPU_TARGET=mips ./build_qemu_support.sh \
    && cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-mips

# MIPS little-endian (MIPSel) — very common in consumer routers
RUN cd qemu_mode && CPU_TARGET=mipsel ./build_qemu_support.sh \
    && cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-mipsel

# AArch64 (ARM 64-bit)
RUN cd qemu_mode && CPU_TARGET=aarch64 ./build_qemu_support.sh \
    && cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-aarch64

# x86 (32-bit)
RUN cd qemu_mode && CPU_TARGET=i386 ./build_qemu_support.sh \
    && cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-i386

# ---------------------------------------------------------------------------
# Stage 2: Lean runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# Runtime dependencies for AFL++ QEMU mode and crash triage
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    gdb-multiarch \
    procps \
    xxd \
    file \
    binutils \
    libglib2.0-0 \
    libpixman-1-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy AFL++ core tools from builder
COPY --from=builder /usr/local/bin/afl-fuzz /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-showmap /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-cmin /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-tmin /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-analyze /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-gotcpu /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-whatsup /usr/local/bin/

# Copy AFL++ runtime support files
COPY --from=builder /usr/local/lib/afl/ /usr/local/lib/afl/

# Copy architecture-specific afl-qemu-trace binaries
COPY --from=builder /usr/local/bin/afl-qemu-trace-arm /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-qemu-trace-mips /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-qemu-trace-mipsel /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-qemu-trace-aarch64 /usr/local/bin/
COPY --from=builder /usr/local/bin/afl-qemu-trace-i386 /usr/local/bin/

# Create working directories
RUN mkdir -p /data/firmware /opt/fuzzing /opt/dictionaries

# Create non-root user for fuzzing
RUN useradd -m -s /bin/bash fuzzer

WORKDIR /opt/fuzzing

# Keep container alive — managed by Docker SDK from the backend
CMD ["sleep", "infinity"]
