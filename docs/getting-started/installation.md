# Installation

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development only)

## Docker (Recommended)

The simplest way to run Wairz is with Docker Compose:

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
docker compose up --build
```

This starts all services:

| Service | URL |
|---------|-----|
| Frontend | [http://localhost:3000](http://localhost:3000) |
| API docs | [http://localhost:8000/docs](http://localhost:8000/docs) |

!!! note
    The first build may take several minutes as it downloads and builds Ghidra, QEMU, and AFL++ containers.

## Local Development

For development with hot-reloading:

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Backend
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Or use the helper script that starts both:

```bash
./launch.sh
```

## Updating

To update to the latest version:

```bash
git pull
docker compose up --build
```

Database migrations run automatically on container startup.

## Troubleshooting

### Port conflicts

If ports 3000 or 8000 are already in use, edit the port mappings in `docker-compose.yml`.

### Docker permissions

On Linux, you may need to add your user to the `docker` group:

```bash
sudo usermod -aG docker $USER
```

Then log out and back in.

### Build failures

If the build fails, try cleaning Docker's build cache:

```bash
docker compose down
docker system prune --filter "label=com.docker.compose.project=wairz"
docker compose up --build
```
