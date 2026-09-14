# AttackLens Production Deployment Guide

This guide provides instructions for deploying the **AttackLens Enterprise Security Intelligence Platform** in production.

---

## 1. Quick Start with Docker Compose (Recommended)

### Prerequisites
- [Docker Engine](https://docs.docker.com/engine/install/) >= 24.0
- [Docker Compose](https://docs.docker.com/compose/install/) >= 2.20

### Step 1: Clone & Configure Environment
```bash
# Copy example environment file
cp .env.docker.example .env

# Generate secure secrets and update .env
# Required updates:
# - POSTGRES_PASSWORD
# - DJANGO_SECRET_KEY
# - DJANGO_ALLOWED_HOSTS (add your domain)
# - CORS_ALLOWED_ORIGINS (add your domain)
```

### Step 2: Build & Start Containers
```bash
# Build and launch in detached mode
docker compose up --build -d

# Verify container health
docker compose ps
```

### Step 3: Access AttackLens
- **Web UI & Security Command Center**: `http://localhost/` (or `http://your-server-ip/`)
- **Backend API**: `http://localhost/api/`
- **Interactive Reports Preview**: `http://localhost/reports`

---

## 2. Architecture Overview

```
                          Internet / Users
                                │
                                ▼
                   ┌─────────────────────────┐
                   │   Nginx Reverse Proxy   │ (Port 80/443)
                   │  (Frontend Container)   │
                   └────────────┬────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             │                                     │
             ▼ (Static SPA Requests)               ▼ (API & Scanner Requests)
   ┌───────────────────┐                 ┌───────────────────┐
   │ React Build (SPA) │                 │  Django + Gunicorn│ (Port 8000)
   │  try_files        │                 │  (Backend Cont.)  │
   └───────────────────┘                 └─────────┬─────────┘
                                                   │
                                                   ▼ (Database)
                                         ┌───────────────────┐
                                         │   PostgreSQL 16   │ (Port 5432)
                                         │  (DB Container)   │
                                         └───────────────────┘
```

---

## 3. Production Hardening Checklist

| Area | Production Standard | Setting in AttackLens |
| :--- | :--- | :--- |
| **Debug Mode** | `DEBUG = False` | `DJANGO_DEBUG=False` in `.env` |
| **Secrets Management** | No hardcoded keys | `DJANGO_SECRET_KEY` injected via env |
| **Database** | PostgreSQL with connection pooling | `postgres:16-alpine` + `CONN_MAX_AGE=600` |
| **Static Files** | Compressed asset serving | `WhiteNoise` with brotli compression |
| **Real-time SSE** | Unbuffered streaming | Nginx `proxy_buffering off;` |
| **Security Headers** | X-Frame, No-Sniff, XSS protection | Enforced in Django & Nginx configs |
| **Health Monitoring** | Automated container health checks | Configured on all 3 services |
| **Data Persistence** | Named Docker volumes | `attacklens_pgdata`, `attacklens_media` |

---

## 4. Maintenance & Operations

### View Application Logs
```bash
# Follow backend logs
docker compose logs -f backend

# Follow frontend / nginx proxy logs
docker compose logs -f frontend

# Follow database logs
docker compose logs -f db
```

### Database Backup & Restore
```bash
# Create backup
docker exec -t attacklens_db pg_dump -U attacklens_user attacklens_db > attacklens_backup_$(date +%Y%m%d).sql

# Restore backup
cat backup.sql | docker exec -i attacklens_db psql -U attacklens_user -d attacklens_db
```

### Stopping Services
```bash
docker compose down
```
