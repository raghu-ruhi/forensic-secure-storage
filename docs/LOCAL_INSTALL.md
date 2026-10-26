# Local Installation Guide (No Docker)

Use this if you want to run the backend and frontend directly on your laptop
for development — faster iteration than rebuilding Docker images each time.
For PostgreSQL setup, see `DATABASE_SETUP.md` first; do that before step 3
below.

---

## Windows 11

### 1. Install prerequisites

- **Python 3.12**: https://www.python.org/downloads/ — during install, check
  "Add python.exe to PATH"
- **Node.js 20 LTS**: https://nodejs.org/
- **PostgreSQL 16**: see `DATABASE_SETUP.md`
- **Git**: https://git-scm.com/download/win
- **VS Code** (optional but recommended): https://code.visualstudio.com/

Verify installs in PowerShell:
```powershell
python --version
node --version
npm --version
git --version
```

### 2. Clone / open the project

```powershell
cd C:\Projects
git clone https://github.com/your-username/forensic-secure-storage.git
cd forensic-secure-storage
```

### 3. Backend setup

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
notepad .env
```

Edit `.env`: set `DATABASE_URL` to match the Postgres user/password/db you
created in `DATABASE_SETUP.md`, and fill in `MAIL_USERNAME`/`MAIL_PASSWORD`
(a Gmail App Password works well — generate one at
https://myaccount.google.com/apppasswords).

```powershell
set FLASK_APP=run:app
flask db upgrade
python run.py
```

You should see Flask start on `http://0.0.0.0:5000`. Leave this terminal
running.

### 4. Frontend setup

Open a **new** PowerShell window:

```powershell
cd C:\Projects\forensic-secure-storage\frontend
npm install
copy .env.example .env
notepad .env
```

Confirm `.env` has:
```
VITE_API_BASE_URL=http://localhost:5000/api
```

```powershell
npm run dev
```

Vite will print a local URL, typically `http://localhost:5173`. Open it in
your browser.

---

## Ubuntu Linux

### 1. Install prerequisites

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip git curl

# Node.js 20 via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# PostgreSQL - see DATABASE_SETUP.md for full setup
sudo apt-get install -y postgresql postgresql-contrib
```

Verify:
```bash
python3.12 --version
node --version
npm --version
git --version
```

VS Code (optional): https://code.visualstudio.com/docs/setup/linux

### 2. Clone the project

```bash
git clone https://github.com/your-username/forensic-secure-storage.git
cd forensic-secure-storage
```

### 3. Backend setup

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
```

Fill in `DATABASE_URL`, `MAIL_USERNAME`, `MAIL_PASSWORD` as described above.

```bash
python run.py
```

Flask starts on `http://0.0.0.0:5000`. Leave this terminal running.

### 4. Frontend setup

Open a new terminal:

```bash
cd forensic-secure-storage/frontend
npm install
cp .env.example .env
nano .env    # confirm VITE_API_BASE_URL=http://localhost:5000/api
npm run dev
```

Open the printed URL (typically `http://localhost:5173`).

---

## Verifying everything works

1. Visit the frontend URL, click **Register**, create an account
2. Check your email (configure `.env` first - see docs/SETUP_WINDOWS_GMAIL.md) for the OTP code
3. Verify the OTP, then log in
4. Upload a small test file as evidence from the Dashboard
5. Open the evidence's detail page and click **Verify Integrity** — you
   should see a green "Hash matches" result

If any step fails, check the backend terminal for a Python traceback and the
browser DevTools console (F12) for frontend errors — both will point at the
specific problem (usually a missing `.env` value or the database not being
reachable).
