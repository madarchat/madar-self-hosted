#!/usr/bin/env bash
# ==============================================================================
# Madar Self-Hosted Sovereign Workspace — Automated Setup & Provisioning Script
# Version: 1.0.0 (MADAR-SRS-SAD-1.0)
# License: AGPL-3.0-only
#
# Usage:
#   ./setup.sh                      # Automatic setup + Web First-Time Wizard
#   ./setup.sh --docker             # Deploy using Docker Compose (recommended)
#   ./setup.sh --native             # Deploy directly on host (Node.js 20+ & PostgreSQL)
#   ./setup.sh --seed-admin         # Pre-seed organization & Super-Admin via CLI (skip web wizard)
#   ./setup.sh --reset-setup        # Re-enable the Web First-Time Registration Wizard (/setup)
#   ./setup.sh --non-interactive    # Unattended setup using .env.setup or defaults
#   ./setup.sh --reconfigure        # Regenerate .env configuration and restart
#   ./setup.sh --check              # Verify health of Core Server & Admin Console
#   ./setup.sh --stop               # Stop running services
#   ./setup.sh --help               # Show usage instructions
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ENV_FILE="$ROOT_DIR/.env"
SETUP_CONF="$ROOT_DIR/.env.setup"
SERVER_DIR="$ROOT_DIR/madar_server"
CONSOLE_DIR="$ROOT_DIR/madar_admin_console"
DEPLOY_DIR="$ROOT_DIR/.deploy"
LOG_DIR="$ROOT_DIR/logs"

DEPLOY_MODE=""
NON_INTERACTIVE=0
RECONFIGURE=0
SEED_ADMIN=0
RESET_SETUP=0
ACTION="install"

# ANSI Colors
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'
  C_CYAN=$'\033[36m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
else
  C_RESET="" C_BOLD="" C_GREEN="" C_CYAN="" C_YELLOW="" C_RED=""
fi

info()  { printf '%s[INFO]%s  %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[OK]%s    %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[WARN]%s  %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()   { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }

usage() {
  cat <<'EOF'
Madar Self-Hosted Sovereign Workspace — Setup Script

Usage:
  ./setup.sh [OPTIONS]

Options:
  --docker             Deploy full stack via Docker Compose (PostgreSQL, Redis, MinIO, Coturn, Core API, Isolated Next.js Admin Console)
  --native             Deploy directly on host using local Node.js (>=20) and PostgreSQL
  --seed-admin         Pre-initialize Workspace & Super-Admin from CLI (skips the browser First-Time Registration Wizard)
  --reset-setup        Re-open the First-Time Organization Registration Wizard (/setup) for re-onboarding
  --non-interactive    Run without prompts using .env.setup or safe defaults
  --update             Rebuild and restart services after 'git pull' while preserving .env and database data
  --reconfigure        Regenerate .env configuration files
  --check              Verify health of Core API, Discovery endpoint, and Isolated Admin Console
  --stop               Stop all running Madar services (Docker or native)
  --help, -h           Display this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker)          DEPLOY_MODE="docker"; shift ;;
    --native)          DEPLOY_MODE="native"; shift ;;
    --update)          NON_INTERACTIVE=1; shift ;;
    --seed-admin)      SEED_ADMIN=1; shift ;;
    --reset-setup)     RESET_SETUP=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --reconfigure)     RECONFIGURE=1; shift ;;
    --check)           ACTION="check"; shift ;;
    --stop)            ACTION="stop"; shift ;;
    --help|-h)         usage; exit 0 ;;
    *)                 die "Unknown option: $1 (run ./setup.sh --help)" ;;
  esac
done

rand_hex() {
  local bytes="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

load_env_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

check_health() {
  local api_port="${API_PORT:-5025}"
  local console_port="${ADMIN_CONSOLE_PORT:-5030}"
  info "Checking Madar Core Server on http://127.0.0.1:${api_port}/health ..."
  if curl -fsS "http://127.0.0.1:${api_port}/health" >/dev/null 2>&1; then
    local health_json
    health_json="$(curl -fsS "http://127.0.0.1:${api_port}/health")"
    ok "Madar Core Server is healthy: $health_json"
  else
    err "Madar Core Server is not reachable on port ${api_port}"
    return 1
  fi

  info "Checking Sovereign Workspace Discovery on http://127.0.0.1:${api_port}/.well-known/madar-workspace.json ..."
  if curl -fsS "http://127.0.0.1:${api_port}/.well-known/madar-workspace.json" >/dev/null 2>&1; then
    ok "Sovereign Workspace Discovery endpoint is active."
  else
    err "Discovery endpoint failed on port ${api_port}"
    return 1
  fi

  info "Checking Isolated Next.js Admin Console BFF on http://127.0.0.1:${console_port}/health ..."
  for _ in {1..20}; do
    if curl -fsS "http://127.0.0.1:${console_port}/health" >/dev/null 2>&1; then
      local console_json
      console_json="$(curl -fsS "http://127.0.0.1:${console_port}/health")"
      ok "Isolated Admin Console BFF is healthy: $console_json"
      return 0
    fi
    sleep 1
  done
  err "Isolated Admin Console BFF is not reachable on port ${console_port}"
  return 1
}

stop_services() {
  info "Stopping Madar Self-Hosted services..."
  if [[ -f "$LOG_DIR/madar_server.pid" ]]; then
    kill "$(cat "$LOG_DIR/madar_server.pid")" 2>/dev/null || true
    rm -f "$LOG_DIR/madar_server.pid"
  fi
  if [[ -f "$LOG_DIR/madar_admin_console.pid" ]]; then
    kill "$(cat "$LOG_DIR/madar_admin_console.pid")" 2>/dev/null || true
    rm -f "$LOG_DIR/madar_admin_console.pid"
  fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose down 2>/dev/null || true
  fi
  ok "All Madar Self-Hosted services stopped."
}

if [[ "$ACTION" == "stop" ]]; then
  stop_services
  exit 0
fi

if [[ "$ACTION" == "check" ]]; then
  load_env_file "$ENV_FILE"
  check_health
  exit 0
fi

# 1. Load optional .env.setup
load_env_file "$SETUP_CONF"

# 2. Determine deployment mode (docker vs native)
if [[ -z "$DEPLOY_MODE" ]]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    DEPLOY_MODE="docker"
  else
    DEPLOY_MODE="native"
  fi
fi

APP_ENV="${APP_ENV:-development}"
WORKSPACE_SLUG="${WORKSPACE_SLUG:-org-hq}"
WORKSPACE_DEFAULT_NAME="${WORKSPACE_DEFAULT_NAME:-Madar Sovereign Workspace}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@madar.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(rand_hex 12)}"  # random unless provided; saved to .env
PUBLIC_HOST="${PUBLIC_HOST:-localhost}"
API_PORT="${API_PORT:-5025}"
ADMIN_CONSOLE_PORT="${ADMIN_CONSOLE_PORT:-5030}"
MINIO_PORT="${MINIO_PORT:-9000}"
STUN_PORT="${STUN_PORT:-3478}"
TURN_PORT="${TURN_PORT:-3479}"

if [[ "$NON_INTERACTIVE" -eq 0 && -t 0 && ( ! -f "$ENV_FILE" || "$RECONFIGURE" -eq 1 ) ]]; then
  printf '\n%s=== Madar Self-Hosted Sovereign Workspace Setup ===%s\n' "$C_BOLD" "$C_RESET"
  printf 'Note: Organization name & initial Super-Admin account will be configured in the browser First-Time Setup Wizard.\n\n'
  read -r -p "Deployment Mode [docker/native] (default: ${DEPLOY_MODE}): " input_mode
  DEPLOY_MODE="${input_mode:-$DEPLOY_MODE}"
  read -r -p "Public Hostname or IP (default: ${PUBLIC_HOST}): " input_host
  PUBLIC_HOST="${input_host:-$PUBLIC_HOST}"
fi

# 3. Generate .env with cryptographic secrets if missing or --reconfigure
if [[ ! -f "$ENV_FILE" || "$RECONFIGURE" -eq 1 ]]; then
  info "Generating cryptographic secrets and writing $ENV_FILE ..."
  JWT_SECRET="${JWT_SECRET:-$(rand_hex 32)}"
  MADAR_MASTER_KEY="${MADAR_MASTER_KEY:-$(rand_hex 32)}"
  CONTROL_PLANE_KEY="${CONTROL_PLANE_KEY:-$(rand_hex 24)}"
  CONTROL_PLANE_HMAC_SECRET="${CONTROL_PLANE_HMAC_SECRET:-$(rand_hex 32)}"
  ADMIN_SESSION_SECRET="${ADMIN_SESSION_SECRET:-$(rand_hex 32)}"
  DB_USER="${DB_USER:-postgres}"
  if [[ "$DEPLOY_MODE" == "docker" ]]; then
    DB_USER="${DB_USER:-madar}"
    DB_PASSWORD="${DB_PASSWORD:-$(rand_hex 16)}"
    DB_HOST="postgres"
  else
    DB_PASSWORD="${DB_PASSWORD:-$(rand_hex 16)}"
    DB_HOST="${DB_HOST:-localhost}"
  fi
  DB_PORT="${DB_PORT:-5432}"
  DB_NAME="${DB_NAME:-madar}"
  REDIS_PASSWORD="${REDIS_PASSWORD:-$(rand_hex 16)}"
  MINIO_ROOT_USER="${MINIO_ROOT_USER:-madar}"
  MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-$(rand_hex 16)}"
  TURN_SECRET="${TURN_SECRET:-$(rand_hex 24)}"

  if [[ "$APP_ENV" == "production" && -n "${API_DOMAIN:-}" ]]; then
    PUBLIC_URL="https://${API_DOMAIN}"
  else
    PUBLIC_URL="http://${PUBLIC_HOST}:${API_PORT}"
  fi

  cat > "$ENV_FILE" <<EOF
# Generated by Madar Self-Hosted setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
APP_ENV=${APP_ENV}
NODE_ENV=${APP_ENV}
DEPLOY_MODE=${DEPLOY_MODE}
DEPLOYMENT_PROFILE=workspace

# Server & Network
PORT=${API_PORT}
API_PORT=${API_PORT}
ADMIN_CONSOLE_PORT=${ADMIN_CONSOLE_PORT}
HOST=0.0.0.0
PUBLIC_HOST=${PUBLIC_HOST}
PUBLIC_URL=${PUBLIC_URL}
API_PREFIX=/api/v1
TRUST_PROXY=1
# Extra browser origins allowed to call the API (comma-separated), e.g. a hosted Madar web client
CORS_ORIGINS=${CORS_ORIGINS:-}

# Workspace Defaults
WORKSPACE_SLUG=${WORKSPACE_SLUG}
WORKSPACE_DEFAULT_NAME="${WORKSPACE_DEFAULT_NAME}"
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Cryptographic Keys (AES-256-GCM Master Key, JWT, Isolated Control-Plane BFF Keys)
JWT_SECRET=${JWT_SECRET}
MADAR_MASTER_KEY=${MADAR_MASTER_KEY}
MASTER_ENCRYPTION_KEY=${MADAR_MASTER_KEY}
ADMIN_API_ENABLED=true
CONTROL_PLANE_KEY=${CONTROL_PLANE_KEY}
ADMIN_PLANE_SECRET=${CONTROL_PLANE_KEY}
CONTROL_PLANE_HMAC_SECRET=${CONTROL_PLANE_HMAC_SECRET}
ADMIN_SESSION_SECRET=${ADMIN_SESSION_SECRET}
COOKIE_SECURE=false

# PostgreSQL Database
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD}
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379

# S3 / MinIO Encrypted Media Storage
MINIO_PORT=${MINIO_PORT}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
MINIO_BUCKET=madar-media
R2_ENABLED=false
R2_ACCESS_KEY_ID=${MINIO_ROOT_USER}
R2_SECRET_ACCESS_KEY=${MINIO_ROOT_PASSWORD}
R2_BUCKET_NAME=madar-media
R2_ENDPOINT=http://${PUBLIC_HOST}:${MINIO_PORT}
R2_PUBLIC_URL=http://${PUBLIC_HOST}:${MINIO_PORT}/madar-media

# WebRTC STUN / Coturn TURN
STUN_ENABLED=true
STUN_PORT=${STUN_PORT}
TURN_ENABLED=true
TURN_PORT=${TURN_PORT}
TURN_SECRET=${TURN_SECRET}
ICE_PUBLIC_HOST=${PUBLIC_HOST}
EOF

  chmod 600 "$ENV_FILE"
  cp "$ENV_FILE" "$SERVER_DIR/.env"
  chmod 600 "$SERVER_DIR/.env"
  ok "Created $ENV_FILE (permissions 600)."
else
  info "Using existing configuration in $ENV_FILE"
  cp "$ENV_FILE" "$SERVER_DIR/.env"
fi

load_env_file "$ENV_FILE"

# 4. Prepare Caddyfile for reverse proxy
mkdir -p "$DEPLOY_DIR"
cat > "$DEPLOY_DIR/Caddyfile" <<EOF
:80 {
  handle /admin* {
    reverse_proxy admin-console:5030
  }
  handle {
    reverse_proxy api:5025
  }
}
EOF

# 5. Execute Deployment Mode
if [[ "$DEPLOY_MODE" == "docker" ]]; then
  info "Starting Madar Self-Hosted stack via Docker Compose..."
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Run with --native or install Docker."
  docker compose up -d --build

  info "Waiting for Core API container to pass health checks..."
  for _ in {1..35}; do
    if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  if [[ "$RESET_SETUP" -eq 1 ]]; then
    info "Resetting setup_completed=false to re-enable First-Time Organization Registration Wizard..."
    docker compose exec -T api node -e "import('./src/db/pool.js').then(async ({db, closePool}) => { await db.query('UPDATE workspace SET setup_completed = FALSE'); await closePool(); })"
  elif [[ "$SEED_ADMIN" -eq 1 ]]; then
    info "Pre-initializing Sovereign Workspace & Super-Admin via madarctl (--seed-admin)..."
    docker compose exec -T api node bin/madarctl.js init-workspace \
      --slug "${WORKSPACE_SLUG}" \
      --name "${WORKSPACE_DEFAULT_NAME}" \
      --domain "${PUBLIC_HOST}" \
      --admin-user "${ADMIN_USER:-EMP-100}" \
      --admin-email "${ADMIN_EMAIL}" \
      --admin-password "${ADMIN_PASSWORD}"
  fi

else
  info "Deploying Madar Self-Hosted in Native Host mode (Node.js + PostgreSQL)..."
  command -v node >/dev/null 2>&1 || die "Node.js (>=20) is required for native mode."
  mkdir -p "$LOG_DIR"

  info "Installing dependencies in madar_server..."
  (cd "$SERVER_DIR" && npm install --no-audit --no-fund)

  info "Running PostgreSQL database migrations..."
  (cd "$SERVER_DIR" && node src/db/migrate.js)

  if [[ "$RESET_SETUP" -eq 1 ]]; then
    info "Resetting setup_completed=false to re-enable First-Time Organization Registration Wizard..."
    (cd "$SERVER_DIR" && node -e "import('./src/db/pool.js').then(async ({db, closePool}) => { await db.query('UPDATE workspace SET setup_completed = FALSE'); await closePool(); })")
  elif [[ "$SEED_ADMIN" -eq 1 ]]; then
    info "Pre-initializing Sovereign Workspace & Super-Admin via madarctl (--seed-admin)..."
    (cd "$SERVER_DIR" && node bin/madarctl.js init-workspace \
      --slug "${WORKSPACE_SLUG}" \
      --name "${WORKSPACE_DEFAULT_NAME}" \
      --domain "${PUBLIC_HOST}" \
      --admin-user "${ADMIN_USER:-EMP-100}" \
      --admin-email "${ADMIN_EMAIL}" \
      --admin-password "${ADMIN_PASSWORD}")
  fi

  info "Installing & building Isolated Next.js Admin Console (App Router + TypeScript + Tailwind CSS)..."
  (
    cd "$CONSOLE_DIR"
    npm install --no-audit --no-fund
    npm run build
  )

  # Stop any previous native processes
  if [[ -f "$LOG_DIR/madar_server.pid" ]]; then
    kill "$(cat "$LOG_DIR/madar_server.pid")" 2>/dev/null || true
  fi
  if [[ -f "$LOG_DIR/madar_admin_console.pid" ]]; then
    kill "$(cat "$LOG_DIR/madar_admin_console.pid")" 2>/dev/null || true
  fi

  info "Starting Madar Core Server (DEPLOYMENT_PROFILE=workspace) on port ${API_PORT}..."
  (
    cd "$SERVER_DIR"
    nohup env \
      DEPLOYMENT_PROFILE=workspace \
      PORT="${API_PORT}" \
      ADMIN_API_ENABLED=true \
      MADAR_MASTER_KEY="${MADAR_MASTER_KEY}" \
      CONTROL_PLANE_KEY="${CONTROL_PLANE_KEY}" \
      ADMIN_PLANE_SECRET="${CONTROL_PLANE_KEY}" \
      CONTROL_PLANE_HMAC_SECRET="${CONTROL_PLANE_HMAC_SECRET}" \
      node src/index.js > "$LOG_DIR/madar_server.log" 2>&1 &
    echo $! > "$LOG_DIR/madar_server.pid"
  )

  info "Starting Isolated Next.js Admin Console BFF (Zero Direct DB Access) on port ${ADMIN_CONSOLE_PORT}..."
  (
    cd "$CONSOLE_DIR"
    nohup env \
      NODE_ENV=production \
      ADMIN_CONSOLE_PORT="${ADMIN_CONSOLE_PORT}" \
      MADAR_CORE_API_URL="http://127.0.0.1:${API_PORT}" \
      MADAR_SERVER_URL="http://127.0.0.1:${API_PORT}" \
      CONTROL_PLANE_KEY="${CONTROL_PLANE_KEY}" \
      ADMIN_PLANE_SECRET="${CONTROL_PLANE_KEY}" \
      CONTROL_PLANE_HMAC_SECRET="${CONTROL_PLANE_HMAC_SECRET}" \
      ADMIN_SESSION_SECRET="${ADMIN_SESSION_SECRET}" \
      COOKIE_SECURE=false \
      npm run start > "$LOG_DIR/madar_admin_console.log" 2>&1 &
    echo $! > "$LOG_DIR/madar_admin_console.pid"
  )

  sleep 3
fi

check_health

SETUP_STATE="$(curl -fsS "http://127.0.0.1:${API_PORT}/.well-known/madar-workspace.json" 2>/dev/null || echo '{}')"

cat <<EOF

${C_BOLD}${C_GREEN}==============================================================================
  Madar Self-Hosted Sovereign Workspace is Ready!
==============================================================================${C_RESET}
  Deployment Mode        : ${DEPLOY_MODE}
  Deployment Profile     : workspace (Sovereign On-Premises)
  Admin Console Stack    : Next.js (App Router) + TypeScript + Tailwind CSS (EN / AR RTL)
  Core API Endpoint      : http://${PUBLIC_HOST}:${API_PORT}
  Discovery Endpoint     : http://${PUBLIC_HOST}:${API_PORT}/.well-known/madar-workspace.json
  Isolated Admin Console : http://${PUBLIC_HOST}:${ADMIN_CONSOLE_PORT}  (Zero Direct DB Access)
EOF

if echo "$SETUP_STATE" | grep -q '"setup_completed":false'; then
  cat <<EOF

${C_BOLD}${C_YELLOW}  >>> NEXT STEP: COMPLETE FIRST-TIME ORGANIZATION REGISTRATION <<<${C_RESET}
  1. Open your browser at: ${C_BOLD}http://${PUBLIC_HOST}:${ADMIN_CONSOLE_PORT}${C_RESET}
  2. The ${C_BOLD}First-Time Organization & Super-Admin Registration Wizard (/setup)${C_RESET}
     will automatically appear (available in English & Arabic RTL).
  3. Register your Organization Identity, Initial Super-Admin Account, and
     Baseline Security Profile.
  4. Once completed, the registration page is permanently locked and your
     interactive 4-Step Employee & Madar Agent Onboarding Guide will open!
==============================================================================
EOF
else
  cat <<EOF

  Workspace Status       : Initialized (setup_completed = true)
  Open Admin Console     : ${C_BOLD}http://${PUBLIC_HOST}:${ADMIN_CONSOLE_PORT}${C_RESET}
  (Tip: Run './setup.sh --reset-setup' if you want to test the First-Time Registration Wizard again)
==============================================================================
EOF
fi
