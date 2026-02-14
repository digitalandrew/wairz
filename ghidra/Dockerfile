FROM eclipse-temurin:17-jdk-jammy

ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# Copy custom scripts
COPY scripts/ /opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts/

# Create non-root user and work directory
RUN useradd -m -s /bin/bash ghidra \
    && mkdir -p /work /data \
    && chown -R ghidra:ghidra /work /data

USER ghidra
WORKDIR /work

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
