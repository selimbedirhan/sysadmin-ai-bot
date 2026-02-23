#!/usr/bin/env bash
# ============================================================
#  STARTUP HEALTH CHECK — ENTRYPOINT SCRIPT
#  Ensures Ollama engine is alive and required models exist
#  before the Core Application starts.
# ============================================================

set -euo pipefail

# --- Configuration ---
OLLAMA_URL="${OLLAMA_BASE_URL:-http://ollama-engine:11434}"
ROUTER_MODEL="${ROUTER_MODEL:-llama3.2:3b}"
EXPERT_MODEL="${EXPERT_MODEL:-llama3.1:8b}"
MAX_RETRIES=60
RETRY_INTERVAL=5

# --- Color Codes ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}============================================${NC}"
echo -e "${YELLOW}  SysAdmin AI Bot — Startup Health Check    ${NC}"
echo -e "${YELLOW}============================================${NC}"

# --- Step 1: Wait for Ollama Engine to be reachable ---
echo -e "\n${YELLOW}[1/3] Waiting for Ollama engine at ${OLLAMA_URL}...${NC}"

retries=0
until curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; do
    retries=$((retries + 1))
    if [ "$retries" -ge "$MAX_RETRIES" ]; then
        echo -e "${RED}[FATAL] Ollama engine did not respond after $((MAX_RETRIES * RETRY_INTERVAL))s. Aborting.${NC}"
        exit 1
    fi
    echo -e "  Attempt ${retries}/${MAX_RETRIES} — retrying in ${RETRY_INTERVAL}s..."
    sleep "$RETRY_INTERVAL"
done

echo -e "${GREEN}[OK] Ollama engine is reachable.${NC}"

# --- Step 2: Verify required models are available ---
echo -e "\n${YELLOW}[2/3] Checking for required models...${NC}"

check_model() {
    local model_name="$1"
    local model_list
    model_list=$(curl -sf "${OLLAMA_URL}/api/tags" | python3 -c "
import sys, json
data = json.load(sys.stdin)
models = [m['name'] for m in data.get('models', [])]
print('\n'.join(models))
" 2>/dev/null || echo "")

    if echo "$model_list" | grep -q "^${model_name}$"; then
        echo -e "  ${GREEN}✓ Model '${model_name}' is loaded.${NC}"
        return 0
    else
        echo -e "  ${YELLOW}⚠ Model '${model_name}' not found. Pulling (this may take several minutes)...${NC}"

        # Stream the pull response — Ollama /api/pull is a streaming endpoint.
        # We pipe output through python to extract and display progress.
        local pull_exit_code
        curl -s --no-buffer "${OLLAMA_URL}/api/pull" \
            -d "{\"name\": \"${model_name}\"}" 2>/dev/null | \
            python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        status = obj.get('status', '')
        if 'completed' in obj and 'total' in obj:
            pct = int(obj['completed'] / obj['total'] * 100) if obj['total'] > 0 else 0
            print(f'  ↳ {status}: {pct}%', end='\r', flush=True)
        elif status:
            print(f'  ↳ {status}', flush=True)
        if obj.get('error'):
            print(f'  ERROR: {obj[\"error\"]}', flush=True)
            sys.exit(1)
    except json.JSONDecodeError:
        pass
print()
" || true

        # Verify the model is now available
        model_list=$(curl -sf "${OLLAMA_URL}/api/tags" | python3 -c "
import sys, json
data = json.load(sys.stdin)
models = [m['name'] for m in data.get('models', [])]
print('\n'.join(models))
" 2>/dev/null || echo "")

        if echo "$model_list" | grep -q "^${model_name}$"; then
            echo -e "  ${GREEN}✓ Model '${model_name}' pulled successfully.${NC}"
            return 0
        else
            echo -e "  ${RED}✗ Failed to pull model '${model_name}'.${NC}"
            return 1
        fi
    fi
}

check_model "$ROUTER_MODEL"
check_model "$EXPERT_MODEL"

# --- Step 3: All systems go ---
echo -e "\n${YELLOW}[3/3] Starting Core Application...${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  All health checks passed. Launching...    ${NC}"
echo -e "${GREEN}============================================${NC}\n"

# Hand off to the CMD defined in Dockerfile
exec "$@"
