# ============================================================
#  CONTAINER 3: MCP SERVER (Model Context Protocol)
#  Purpose : Tool execution layer — SSH, Ping, System Monitoring
#  Resource: ~1 CPU core, ~1.5 GB RAM
#  Network : Internal only — has SSH access to target machines
# ============================================================

FROM python:3.11-slim

LABEL maintainer="Turkcell AI Infrastructure Team"
LABEL description="MCP tool execution server for SysAdmin AI Bot"

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# --- System Dependencies (SSH client, network tools) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# --- Python Dependency Installation (cached layer) ---
COPY mcp_server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# --- Application Source ---
COPY mcp_server/ /app/mcp_server/

EXPOSE 8100

CMD ["python", "-m", "uvicorn", "mcp_server.server:app", "--host", "0.0.0.0", "--port", "8100"]
