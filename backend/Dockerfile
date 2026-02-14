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
    && rm -rf /var/lib/apt/lists/*

# Install sasquatch for non-standard SquashFS
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && ./build.sh \
    || true \
    && rm -rf /tmp/sasquatch

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

# Create data directory
RUN mkdir -p /data/firmware && chown -R wairz:wairz /data /app

USER wairz

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
