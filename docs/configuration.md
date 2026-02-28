# Configuration

All Wairz settings are configured via environment variables or a `.env` file in the project root. Copy `.env.example` to `.env` to get started:

```bash
cp .env.example .env
```

## Environment Variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://wairz:wairz@postgres:5432/wairz` | PostgreSQL connection string (asyncpg driver) |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `STORAGE_ROOT` | `/data/firmware` | Directory where firmware files are stored on disk |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Firmware

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_UPLOAD_SIZE_MB` | `500` | Maximum firmware upload size in megabytes |
| `MAX_TOOL_OUTPUT_KB` | `30` | MCP tool output truncation limit in kilobytes |

### Ghidra

| Variable | Default | Description |
|----------|---------|-------------|
| `GHIDRA_PATH` | `/opt/ghidra` | Ghidra headless installation path |
| `GHIDRA_SCRIPTS_PATH` | `/opt/ghidra-scripts` | Custom Ghidra analysis scripts path |
| `GHIDRA_TIMEOUT` | `120` | Decompilation timeout in seconds |

### Emulation

| Variable | Default | Description |
|----------|---------|-------------|
| `EMULATION_IMAGE` | `wairz-emulation` | Docker image for QEMU containers |
| `EMULATION_NETWORK` | `emulation_net` | Docker network for emulation containers |

### Fuzzing

| Variable | Default | Description |
|----------|---------|-------------|
| `FUZZING_IMAGE` | `wairz-fuzzing` | Docker image for AFL++ containers |
| `FUZZING_TIMEOUT_MINUTES` | `120` | Maximum fuzzing campaign duration in minutes |
| `FUZZING_MAX_CAMPAIGNS` | `1` | Maximum concurrent fuzzing campaigns per project |

### UART Bridge

| Variable | Default | Description |
|----------|---------|-------------|
| `UART_BRIDGE_HOST` | `host.docker.internal` | Hostname of the UART bridge on the host machine |
| `UART_BRIDGE_PORT` | `9999` | TCP port the UART bridge listens on |

### External APIs

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(empty)* | Optional NVD API key for higher rate limits during CVE scanning |

## Docker Compose

The default `docker-compose.yml` starts all services. Key port mappings:

| Service | Host Port | Container Port |
|---------|-----------|----------------|
| Frontend | 3000 | 3000 |
| Backend API | 8000 | 8000 |
| PostgreSQL | 5432 | 5432 |
| Redis | 6379 | 6379 |

## Local Development

For local development without Docker, set the database and Redis URLs to point to your local instances:

```env
DATABASE_URL=postgresql+asyncpg://wairz:wairz@localhost:5432/wairz
REDIS_URL=redis://localhost:6379/0
STORAGE_ROOT=./data/firmware
```
