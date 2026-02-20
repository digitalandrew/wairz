FROM debian:bookworm-slim

# Install AFL++ with QEMU mode, GDB for crash triage, and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
    qemu-user-static \
    gdb-multiarch \
    procps \
    xxd \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Create working directories
RUN mkdir -p /data/firmware /opt/fuzzing /opt/dictionaries

# Create non-root user for fuzzing
RUN useradd -m -s /bin/bash fuzzer

WORKDIR /opt/fuzzing

# Keep container alive — managed by Docker SDK from the backend
CMD ["sleep", "infinity"]
