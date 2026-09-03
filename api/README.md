# SecureAI API (live package)

Self-contained FastAPI service for production. The research monorepo at the repo root (`web/`, `admin/`, notebooks, etc.) stays as-is.

## What’s included

| Path | Role |
|------|------|
| `src/` | Pipeline + public + admin routes |
| `configs/` | `config.yaml` |
| `models/detector/` | Trained Layer 2 models |
| `data/attack_bank.json` | Similarity bank |
| `data/team_overrides.json` | Exact Lab overrides (if present) |
| `data/processed/train.jsonl` | For Lab retrain on the live host |
| `run_api.py` | Entrypoint |
| `Dockerfile` | Container deploy |

## Quick start (VPS / local)

```bash
cd api
cp .env.example .env
# edit .env — set ADMIN_INTERNAL_TOKEN and CORS_ORIGINS

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
python run_api.py
```

API: `http://HOST:8000` · Docs: `/docs` · Health: `/health`

## Sync from monorepo (after Lab / retrain locally)

From the **Prompt** repo root:

```powershell
powershell -File api\sync_from_project.ps1
```

Then redeploy this `api/` folder (or rebuild the Docker image).

## Docker

```bash
cd api
cp .env.example .env
# fill .env

docker build -t secureai-api .
docker run --env-file .env -p 8000:8000 -v secureai-data:/app/data secureai-api
```

Mount `data/` as a volume so inbox / overrides / train merges survive restarts.

## Live checklist

1. Set a strong `ADMIN_INTERNAL_TOKEN` (same value in the admin Node app if you host Lab).
2. Set `CORS_ORIGINS` to your real chat/admin HTTPS origins.
3. Point public chat (`web`) `PYTHON_API_URL` / proxy at this API.
4. Do **not** expose admin routes without the token; keep Lab on a private network if possible.
5. After local research Train, run `sync_from_project.ps1` before shipping model/bank updates.

## Deploy on Render

**Almost ready** after the fixes below. Use the **lighter** deps file (no PyTorch).

### Dashboard setup

1. Push this repo to GitHub (include `api/models/detector/*.pkl` — ~4MB).
2. Render → **New Web Service** → connect repo.
3. Settings:
   - **Root Directory:** `api`
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements-render.txt`
   - **Start Command:** `python run_api.py`
   - **Health Check Path:** `/health`
4. Environment:
   - `ADMIN_INTERNAL_TOKEN` = long random secret
   - `CORS_ORIGINS` = `https://your-chat-frontend.com` (comma-separated)
   - `PYTHON_VERSION` = `3.12.8` (optional)

Or use Blueprint: [`render.yaml`](render.yaml) (Root Directory still `api` if nested).

### What works on Render Starter

| Feature | Status |
|---------|--------|
| `/detect-conversational`, `/health` | Yes |
| Layer 1–3 + attack bank + overrides | Yes |
| Layer 2b DeBERTa (torch) | No — uses heuristic fallback with `requirements-render.txt` |
| Lab Train (full retrain) | Poor fit — ephemeral disk + slow CPU; do Train locally then sync |
| Free tier | Often too small / spins down |

### After local Train

```powershell
powershell -File api\sync_from_project.ps1
git add api/models api/data/attack_bank.json api/src api/configs
git commit -m "Sync API models for Render"
git push
```

### Relation to the main project

```
Prompt/                 ← research + local demo (unchanged)
  web/                  ← chat UI
  admin/                ← Lab UI
  src/ …                ← source of truth while developing
  api/                  ← THIS folder — copy/sync for live host
```
