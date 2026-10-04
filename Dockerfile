# ------------------------------------------------------------
# Build React frontend
# ------------------------------------------------------------
FROM node:20-slim AS frontend-builder

WORKDIR /frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend ./
RUN npm run build


# ------------------------------------------------------------
# Production FastAPI + TShark
# ------------------------------------------------------------
FROM python:3.11-slim

# Install TShark / Wireshark CLI
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       tshark \
    && rm -rf /var/lib/apt/lists/*

# Explicit TShark path
ENV TSHARK_PATH=/usr/bin/tshark
ENV PYTHONUNBUFFERED=1

# Verify TShark is installed during Docker build
RUN which tshark && tshark --version

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY app ./app

# Copy the production React build.
# app/main.py serves frontend/dist/index.html at / when present.
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# Start FastAPI
CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"
