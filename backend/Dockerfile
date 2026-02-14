FROM python:3.12-slim AS base

# Install system dependencies for firmware analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    squashfs-tools \
    mtd-utils \
    e2fsprogs \
    cpio \
    p7zip-full \
    file \
    libmagic1 \
    radare2 \
    build-essential \
    git \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install sasquatch for non-standard SquashFS
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && ./build.sh \
    || true \
    && rm -rf /tmp/sasquatch

# Install OpenJDK 17 for Ghidra
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user
RUN useradd -m -s /bin/bash wairz

# Set up working directory
WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --no-dev --no-editable 2>/dev/null || uv sync --no-editable

# Copy application code
COPY . .

# Create data and Ghidra project directories
RUN mkdir -p /data/firmware /tmp/ghidra_projects \
    && chown -R wairz:wairz /data /app /tmp/ghidra_projects /opt/ghidra

USER wairz

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
