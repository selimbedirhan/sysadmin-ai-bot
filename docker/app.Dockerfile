# ============================================================
#  CONTAINER 2: CORE APPLICATION
#  Purpose : LangChain orchestration, dynamic routing, RBAC
#  Resource: ~1 CPU core, ~2 GB RAM
#  Depends : ollama-engine (health), mcp-server (runtime)
# ============================================================

FROM python:3.11-slim

LABEL maintainer="Turkcell AI Infrastructure Team"
LABEL description="Core LangChain application for SysAdmin AI Bot"

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# --- System Dependencies (curl needed by entrypoint.sh for health checks) ---
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# --- Dependency Installation (cached layer) ---
COPY core_app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# --- Application Source ---
COPY core_app/ /app/core_app/
COPY config/  /app/config/

# --- Entrypoint Script ---
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "core_app/main.py"]
