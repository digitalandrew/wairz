# Wairz

AI-assisted firmware reverse engineering and security assessment platform. Upload firmware images, unpack them, explore the filesystem, and analyze binaries — all augmented by an AI assistant.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development)

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
```

Edit `.env` and set your `ANTHROPIC_API_KEY`.

### 2. Start services

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Install dependencies and run migrations
cd backend
uv sync
uv run alembic upgrade head
```

### 3. Run the backend

```bash
cd backend
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API is now available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Alternative: Full Docker deployment

```bash
cp .env.example .env
# Edit .env with your settings
docker compose up --build
```

## Usage

### Create a project

```bash
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "My Router", "description": "TP-Link firmware analysis"}'
```

### Upload firmware

```bash
curl -X POST http://localhost:8000/api/v1/projects/{project_id}/firmware \
  -F "file=@firmware.bin"
```

### Unpack firmware

```bash
curl -X POST http://localhost:8000/api/v1/projects/{project_id}/firmware/unpack
```

### Browse extracted filesystem

```bash
# List root directory
curl "http://localhost:8000/api/v1/projects/{project_id}/files?path=/"

# Read a file
curl "http://localhost:8000/api/v1/projects/{project_id}/files/read?path=/etc/passwd"

# Get file metadata (type, hashes, ELF headers)
curl "http://localhost:8000/api/v1/projects/{project_id}/files/info?path=/bin/busybox"

# Search for files
curl "http://localhost:8000/api/v1/projects/{project_id}/files/search?pattern=*.conf"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/projects` | Create project |
| `GET` | `/api/v1/projects` | List projects |
| `GET` | `/api/v1/projects/{id}` | Get project details |
| `PATCH` | `/api/v1/projects/{id}` | Update project |
| `DELETE` | `/api/v1/projects/{id}` | Delete project |
| `POST` | `/api/v1/projects/{id}/firmware` | Upload firmware |
| `GET` | `/api/v1/projects/{id}/firmware` | Get firmware metadata |
| `POST` | `/api/v1/projects/{id}/firmware/unpack` | Unpack firmware |
| `GET` | `/api/v1/projects/{id}/files` | List directory |
| `GET` | `/api/v1/projects/{id}/files/read` | Read file contents |
| `GET` | `/api/v1/projects/{id}/files/info` | File metadata |
| `GET` | `/api/v1/projects/{id}/files/search` | Search files by glob |

## Project Structure

```
wairz/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # Async SQLAlchemy
│   │   ├── models/              # ORM models
│   │   ├── schemas/             # Pydantic schemas
│   │   ├── routers/             # API endpoints
│   │   ├── services/            # Business logic
│   │   ├── workers/             # Firmware unpacking
│   │   └── utils/               # Path validation, sandboxing
│   ├── alembic/                 # Database migrations
│   ├── Dockerfile
│   └── pyproject.toml
├── scripts/
│   └── setup.sh                 # First-time setup helper
├── docker-compose.yml
├── .env.example
└── CLAUDE.md                    # Full project specification
```

## Configuration

All settings are configured via environment variables (or `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://wairz:wairz@localhost:5432/wairz` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `ANTHROPIC_API_KEY` | — | API key for AI features |
| `STORAGE_ROOT` | `/data/firmware` | Firmware storage directory |
| `MAX_UPLOAD_SIZE_MB` | `500` | Maximum firmware upload size |
| `LOG_LEVEL` | `INFO` | Logging level |

## License

[AGPL-3.0](LICENSE)
