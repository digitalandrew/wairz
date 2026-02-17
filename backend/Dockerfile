FROM python:3.12-slim AS base

# Install system dependencies for firmware analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    sleuthkit \
    squashfs-tools \
    cramfsswap \
    mtd-utils \
    e2fsprogs \
    cpio \
    p7zip-full \
    cabextract \
    lzop \
    srecord \
    file \
    libmagic1 \
    build-essential \
    git \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    wget \
    curl \
    unzip \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based firmware extraction tools used by binwalk
RUN pip3 install --no-cache-dir --break-system-packages \
    jefferson \
    ubi_reader \
    && pip3 install --no-cache-dir --break-system-packages \
       git+https://github.com/devttys0/yaffshiv.git 2>/dev/null \
    || echo "WARN: yaffshiv install failed — YAFFS extraction won't work"

# Install radare2 from GitHub releases (not in Debian Trixie repos)
RUN curl -fsSL https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb -o /tmp/radare2.deb \
    && dpkg -i /tmp/radare2.deb || apt-get install -f -y \
    && rm /tmp/radare2.deb

# Install sasquatch for non-standard SquashFS (vendor-modified)
# Try the devttys0 fork first; patch out -Werror to handle newer compiler warnings
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && sed -i 's/-Werror//g' squashfs-tools/Makefile patches/*.patch 2>/dev/null \
    && sed -i 's/-Wall -Werror/-Wall/g' squashfs-tools/Makefile 2>/dev/null; \
    cd /tmp/sasquatch && ./build.sh 2>/dev/null \
    && cp /usr/local/bin/sasquatch /usr/local/bin/sasquatch 2>/dev/null; \
    rm -rf /tmp/sasquatch; \
    which sasquatch || echo "WARN: sasquatch build failed — non-standard SquashFS won't extract"

# Install OpenJDK 21 for Ghidra (JDK 17 not available in Trixie)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
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

# Create non-root user and add to docker group for emulation container management.
# The docker socket GID from the host is passed via build arg (default 999).
ARG DOCKER_GID=999
RUN groupadd -g ${DOCKER_GID} docker || true \
    && useradd -m -s /bin/bash wairz \
    && usermod -aG docker wairz

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
