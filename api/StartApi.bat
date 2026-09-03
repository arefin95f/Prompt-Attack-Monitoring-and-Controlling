@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating venv...
  python -m venv .venv
  .venv\Scripts\pip install -r requirements.txt
)
if not exist ".env" (
  copy .env.example .env
  echo Created .env — edit ADMIN_INTERNAL_TOKEN and CORS_ORIGINS before public deploy.
)
.venv\Scripts\python.exe run_api.py
pause
