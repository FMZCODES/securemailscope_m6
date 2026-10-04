FROM python:3.11-slim

# Install TShark / Wireshark CLI
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY app ./app

# Render provides PORT
ENV PYTHONUNBUFFERED=1

CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"