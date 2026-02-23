# ============================================================
#  CONTAINER 1: OLLAMA ENGINE
#  Purpose : Hosts and serves LLM models (llama3.2:3b, llama3.1:8b)
#  Resource: ~4 CPU cores, ~7 GB RAM (inference-priority)
# ============================================================

FROM ollama/ollama:latest

LABEL maintainer="Turkcell AI Infrastructure Team"
LABEL description="Ollama inference engine for SysAdmin AI Bot"

# Install curl for Docker healthcheck (not included in base image)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Persistent model storage is mounted via docker-compose volume.
# Models are pulled at first boot via entrypoint, not baked into the image.

EXPOSE 11434

# Default entrypoint from the base image starts the Ollama server.
# No modifications needed — the base image handles everything.

