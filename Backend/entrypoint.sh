#!/bin/sh
set -e

echo "=== AttackLens Production Container Startup ==="

# Wait for database if configured
if [ -n "$DB_HOST" ] || [ -n "$DATABASE_URL" ]; then
  echo "Waiting for database connection..."
  python - << 'EOF'
import os
import sys
import time
from urllib.parse import urlparse

db_url = os.environ.get('DATABASE_URL')
if db_url:
    parsed = urlparse(db_url)
    host = parsed.hostname or 'localhost'
    port = parsed.port or 5432
    user = parsed.username or 'postgres'
    password = parsed.password or ''
    dbname = parsed.path.lstrip('/') or 'postgres'
else:
    host = os.environ.get('DB_HOST', 'localhost')
    port = int(os.environ.get('DB_PORT', 5432))
    user = os.environ.get('DB_USER', 'postgres')
    password = os.environ.get('DB_PASSWORD', '')
    dbname = os.environ.get('DB_NAME', 'postgres')

# Attempt connection with retries
try:
    import psycopg2
    max_retries = 30
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                dbname=dbname,
                connect_timeout=3
            )
            conn.close()
            print(f"Database at {host}:{port}/{dbname} is ready!")
            sys.exit(0)
        except Exception as e:
            if i < max_retries - 1:
                time.sleep(1)
            else:
                print(f"Database connection warning after {max_retries} attempts: {e}")
                sys.exit(0)
except ImportError:
    pass
EOF
fi

# Run Database Migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Collect Static Files for WhiteNoise / Nginx
echo "Collecting static files..."
python manage.py collectstatic --noinput --clear || true

# Launch Gunicorn Server
echo "Starting Gunicorn WSGI HTTP Server on 0.0.0.0:8000..."
exec gunicorn src.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --threads 2 \
    --worker-class gthread \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --log-level info \
    --access-logfile - \
    --error-logfile -
