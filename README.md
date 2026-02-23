# ATLAS — Turkcell SysAdmin AI Bot

> Agentic AI system administrator for enterprise Linux infrastructure.

## Architecture

```
┌─────────────────────────────────────────────┐
│            Docker Compose Network           │
│                                             │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │  Ollama   │  │  Core App │  │   MCP    │ │
│  │  Engine   │←─│  (Brain)  │─→│  Server  │ │
│  │ Container1│  │ Container2│  │Container3│ │
│  └──────────┘  └───────────┘  └──────────┘ │
│  llama3.2:3b    LangChain     FastAPI       │
│  llama3.1:8b    + RBAC        + SSH/Net     │
└─────────────────────────────────────────────┘
```

| Container | Purpose | Port |
|-----------|---------|------|
| **ollama-engine** | LLM inference (3B router + 8B expert) | 11434 |
| **core-app** | Query routing, RBAC, Rich terminal UI | — |
| **mcp-server** | Tool execution (SSH, network diagnostics) | 8100 |

## Quick Start

```bash
# 1. Copy environment template and configure
cp .env.example .env
# Edit .env — set SSH_TARGET_HOST, SSH_TARGET_USER, etc.

# 2. Build and start all containers
docker compose up --build -d

# 3. Attach to the interactive terminal
docker attach sysadmin-core-app
```

> **Note:** First run pulls AI models (~5 GB). This may take several minutes.

## Available Tools

| Tool | Actions | Description |
|------|---------|-------------|
| `linux_ssh` | `execute_command`, `test_connection` | Remote SSH command execution |
| `network_monitor` | `ping`, `dns_lookup`, `check_routes` | Local network diagnostics |

## RBAC Roles

| Role | Permissions | Safety Level |
|------|-------------|--------------|
| `admin` | Full access (SSH, services, firewall, users) | 🔴 Dangerous (with confirmation) |
| `junior` | Read-only diagnostics (monitoring, logs, network) | 🟢 Safe only |

## Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `whoami` | Display current user and role |
| `status` | Run system connectivity checks |
| `history` | Show conversation message count |
| `clear` | Clear the terminal screen |
| `exit` | Exit the application |

## Project Structure

```
sysadmin-ai-bot/
├── docker-compose.yml          # Container orchestration
├── docker/
│   ├── ollama.Dockerfile       # LLM inference container
│   ├── app.Dockerfile          # Core application container
│   ├── mcp.Dockerfile          # MCP tool server container
│   └── entrypoint.sh           # Model pull + health checks
├── config/
│   ├── sysadmin_persona.yaml   # AI identity + prompts
│   ├── rbac_roles.yaml         # Roles, users, permissions
│   └── system_settings.yaml    # Model params, timeouts, safety
├── core_app/
│   ├── main.py                 # Interactive terminal (Rich UI)
│   ├── router_agent.py         # Query routing + LLM orchestration
│   ├── rbac_security.py        # Permission validation
│   └── requirements.txt
└── mcp_server/
    ├── server.py               # FastAPI tool execution API
    ├── tools/
    │   ├── base_tool.py        # Abstract tool interface
    │   ├── linux_ssh.py        # SSH command executor
    │   └── network_monitor.py  # Ping, DNS, route tools
    └── requirements.txt
```

## License

Internal use only — Turkcell Technology.
