# ==============================================================================
# LLM Security Research Platform - Backend Dockerfile
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install required system libraries (for libpq/PostgreSQL & PDF processing)
# and Linux Cybersecurity Tool Stack (YARA, ClamAV, tshark)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    yara \
    clamav \
    clamav-daemon \
    tshark \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Set packet capture capability on dumpcap to allow unprivileged network monitoring
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap || true

# Install python dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy source code, rules, and initial datasets
COPY app/ /app/app/
COPY rules/ /app/rules/
COPY frontend/ /app/frontend/
COPY backend/ /app/backend/
COPY dataset/ /app/dataset/

# Create a non-privileged user for enhanced container security
RUN groupadd -r appuser && useradd -r -g appuser appuser && \
    mkdir -p /app/quarantine && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Launch FastAPI via uvicorn with modular security gateway
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
