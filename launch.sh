#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

cleanup() {
    echo ""
    echo "Shutting down..."
    [ -n "${FRONTEND_PID:-}" ] && kill "$FRONTEND_PID" 2>/dev/null
    exit 0
}
trap cleanup INT TERM

# Create .env if missing
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    cat > "$SCRIPT_DIR/.env" <<EOF
DATABASE_URL=postgresql+asyncpg://wairz:wairz@localhost:5432/wairz
REDIS_URL=redis://localhost:6379/0
ANTHROPIC_API_KEY=
STORAGE_ROOT=./data/firmware
EOF
    echo "Created .env — set ANTHROPIC_API_KEY for AI features"
fi

# Start containers
echo "Starting PostgreSQL and Redis..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d postgres redis

# Wait for postgres
echo "Waiting for PostgreSQL..."
until docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T postgres pg_isready -U wairz &>/dev/null; do
    sleep 1
done

# Install deps + migrate
echo "Installing dependencies..."
cd "$BACKEND_DIR"
uv sync --quiet

echo "Running migrations..."
uv run alembic upgrade head

# Install frontend deps if needed
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo "Installing frontend dependencies..."
    cd "$FRONTEND_DIR"
    npm install --silent
fi

# Start frontend dev server in background
echo "Starting frontend on http://localhost:5173"
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

# Start backend
cd "$BACKEND_DIR"
echo ""
echo "Backend:  http://localhost:8000  (API docs: /docs)"
echo "Frontend: http://localhost:5173"
echo "Press Ctrl+C to stop"
echo ""
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
