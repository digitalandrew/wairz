#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Wairz Setup ==="

# Check prerequisites
for cmd in docker; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

# Create .env if it doesn't exist
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "Creating .env from .env.example..."
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    echo "Please edit .env and set your ANTHROPIC_API_KEY"
fi

# Start services
echo "Starting services..."
docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d postgres redis

# Wait for postgres
echo "Waiting for PostgreSQL to be ready..."
until docker compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T postgres pg_isready -U wairz &> /dev/null; do
    sleep 1
done
echo "PostgreSQL is ready."

# Run migrations
echo "Running database migrations..."
cd "$PROJECT_ROOT/backend"
if command -v uv &> /dev/null; then
    uv run alembic upgrade head
else
    echo "uv not found. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo ""
echo "=== Setup complete! ==="
echo "Start the backend:  cd backend && uv run uvicorn app.main:app --reload"
echo "Or use Docker:      docker compose up --build"
