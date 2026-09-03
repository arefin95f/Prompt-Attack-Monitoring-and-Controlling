#!/usr/bin/env python3
"""SecureAI API — live / local entrypoint (run from the api/ folder)."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

import uvicorn

if __name__ == "__main__":
    host = os.getenv("API_HOST", "0.0.0.0")
    # Render injects PORT; local/docker can use API_PORT
    port = int(os.getenv("PORT") or os.getenv("API_PORT") or "8000")
    print("=" * 60)
    print("SecureAI Prompt Injection Defense API")
    print(f"Listening: http://{host}:{port}")
    print(f"Docs:      http://{host}:{port}/docs")
    print(f"Health:    http://{host}:{port}/health")
    print("=" * 60)
    uvicorn.run(
        "src.api.app:app",
        host=host,
        port=port,
        reload=False,
        log_level=os.getenv("LOG_LEVEL", "info"),
        workers=1,
    )
