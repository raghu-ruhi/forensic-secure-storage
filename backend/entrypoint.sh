#!/bin/sh
set -e

echo "Waiting for PostgreSQL to become available..."
python3 - <<'PYEOF'
import os
import time
import psycopg2

url = os.environ.get("DATABASE_URL", "")
if url.startswith("postgresql://"):
    for attempt in range(30):
        try:
            conn = psycopg2.connect(url)
            conn.close()
            print("Database is up.")
            break
        except Exception as exc:
            print(f"  ...not ready yet ({exc}), retrying in 2s")
            time.sleep(2)
    else:
        raise SystemExit("Database never became available.")
else:
    print("Non-Postgres DATABASE_URL, skipping wait.")
PYEOF

echo "Checking whether this database predates Flask-Migrate (stamp only, no schema change)..."
export FLASK_APP=run:app
python3 -c "
from app import create_app
from app.migration_adopt import adopt_legacy_schema
app = create_app()
with app.app_context():
    print('migration state:', adopt_legacy_schema())
"

echo "Applying database migrations (flask db upgrade)..."
flask db upgrade

echo "Seeding initial admin (only if configured and none exists)..."
python3 -c "
from app import create_app
from app.db_bootstrap import seed_initial_admin
app = create_app()
with app.app_context():
    seed_initial_admin()
"

echo "Starting server..."
exec "$@"
