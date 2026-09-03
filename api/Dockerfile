# SecureAI live API (FastAPI)
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV API_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Render sets $PORT; local defaults to 8000 inside run_api.py
CMD ["python", "run_api.py"]
