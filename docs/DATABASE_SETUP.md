# PostgreSQL Setup Guide

## Option A: Docker (recommended, matches production)

If you're using `docker compose up`, Postgres is already configured for you
via the `db` service in `docker-compose.yml` — skip to "Verifying the
connection" below. This section is for a **local, non-Docker** Postgres
install (useful if you want to run the Flask backend directly with
`python run.py` while developing).

## Option B: Local install — Windows 11

1. Download the installer from https://www.postgresql.org/download/windows/
2. Run it, accept defaults, and when prompted **set a password for the
   `postgres` superuser** — remember it.
3. Keep the default port `5432`.
4. Finish the installer. It also installs **pgAdmin 4** (a GUI) and **psql**
   (command line), both under a new Start Menu folder "PostgreSQL 16".
5. Open **SQL Shell (psql)** from the Start Menu. Press Enter through the
   prompts (Server=localhost, Database=postgres, Port=5432, Username=postgres)
   until it asks for the password you set in step 2.

## Option B: Local install — Ubuntu Linux

```bash
sudo apt-get update
sudo apt-get install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Log in as the postgres system user to get a psql shell
sudo -u postgres psql
```

## Create the database, user, and grant privileges

Once you have a `psql` prompt (either OS), run:

```sql
CREATE DATABASE forensic_db;
CREATE USER forensic_user WITH PASSWORD 'StrongPass123!';
GRANT ALL PRIVILEGES ON DATABASE forensic_db TO forensic_user;

-- PostgreSQL 15+ requires this extra grant on the public schema:
\c forensic_db
GRANT ALL ON SCHEMA public TO forensic_user;
```

Type `\q` to exit psql.

**Change `StrongPass123!` to something you control** — it must match the
password in your `.env` file's `DATABASE_URL`.

## Configure password authentication (Ubuntu only)

By default Ubuntu's Postgres uses `peer` authentication for local
connections, which won't accept the app's username/password login. Fix it:

```bash
sudo find / -name "pg_hba.conf" 2>/dev/null
# typically /etc/postgresql/16/main/pg_hba.conf
sudo nano /etc/postgresql/16/main/pg_hba.conf
```

Find the lines near the bottom that look like:
```
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
```
Change `peer` to `md5` (or leave `scram-sha-256` as-is for `host` connections
— that already works for TCP connections, which is what the Flask app uses).

Restart Postgres:
```bash
sudo systemctl restart postgresql
```

## Test the connection

```bash
psql -h localhost -U forensic_user -d forensic_db
# enter the password when prompted
```

If you see a `forensic_db=>` prompt, the connection works.

## Point the backend at it

In `backend/.env`:
```
DATABASE_URL=postgresql://forensic_user:StrongPass123!@localhost:5432/forensic_db
```

## Creating the tables

The backend uses SQLAlchemy models (see `backend/app/models/`). Tables are
created automatically the first time the app runs:

```
cd backend
set FLASK_APP=run:app            (Linux/macOS: export FLASK_APP=run:app)
flask db upgrade
python run.py
```

The schema is created and updated **only** by Flask-Migrate (`flask db upgrade`); the application no longer calls
`db.create_all()` or alters tables at startup. Docker runs the upgrade automatically. Details, rollback and adopting an
older database: [`MIGRATIONS.md`](MIGRATIONS.md).

## Inspecting the data (optional)

```sql
\c forensic_db
\dt                              -- list tables
SELECT id, email, role FROM users;
SELECT case_number, status FROM evidence;
```
