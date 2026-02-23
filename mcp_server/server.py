"""
MCP Server — FastAPI Application
==================================
The Model Context Protocol server that exposes tools as HTTP endpoints.
This is Container 3 — the "robotic arms" of the SysAdmin AI Bot.

Architecture:
  - Tools are auto-discovered at startup via a registry pattern.
  - Every tool implements BaseTool and is registered by name.
  - The Core App (Container 2) sends ToolRequests via HTTP POST.
  - The server routes requests to the correct tool and returns ToolResults.

SOLID Principles Applied:
  - S: Server only handles HTTP routing — all logic lives in tools.
  - O: New tools are added by creating a class + registering it (no server changes).
  - L: All tools are interchangeable through the BaseTool interface.
  - I: Server exposes a minimal API surface.
  - D: Server depends on BaseTool abstraction, not concrete tool classes.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from mcp_server.tools.base_tool import BaseTool, ToolRequest, ToolResult, ToolResultStatus
from mcp_server.tools.linux_ssh import LinuxSSHTool
from mcp_server.tools.network_monitor import NetworkMonitorTool

# ============================================================
#  LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mcp_server")


# ============================================================
#  TOOL REGISTRY
#  Maps tool names → tool instances.
#  To add a new tool:
#    1. Create a class implementing BaseTool in tools/
#    2. Import it here
#    3. Add it to _register_tools()
#  The server code itself never changes.
# ============================================================

class ToolRegistry:
    """
    Central registry for all MCP tools.

    Provides O(1) lookup by tool name and enforces uniqueness.
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool. Raises ValueError on duplicate names."""
        if tool.name in self._tools:
            raise ValueError(
                f"Duplicate tool name: '{tool.name}' is already registered."
            )
        self._tools[tool.name] = tool
        logger.info(
            "Registered tool: '%s' — %s (actions: %s)",
            tool.name, tool.description, tool.supported_actions,
        )

    def get(self, name: str) -> BaseTool | None:
        """Retrieve a tool by name, or None if not found."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """Return metadata for all registered tools."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "supported_actions": tool.supported_actions,
            }
            for tool in self._tools.values()
        ]

    @property
    def tool_count(self) -> int:
        return len(self._tools)


# ============================================================
#  REGISTRY INITIALIZATION
# ============================================================

def _create_registry() -> ToolRegistry:
    """
    Factory: build and populate the tool registry.

    Add new tools here as the system grows.
    This is the ONLY place that knows about concrete tool classes.
    """
    registry = ToolRegistry()
    registry.register(LinuxSSHTool())
    registry.register(NetworkMonitorTool())
    return registry


# ============================================================
#  LIFESPAN — Replaces deprecated @app.on_event()
# ============================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Application lifespan: startup and shutdown logic."""
    # --- Startup ---
    logger.info(
        "╔══════════════════════════════════════════════╗"
    )
    logger.info(
        "║   MCP Server started — %d tools registered   ║",
        registry.tool_count,
    )
    logger.info(
        "╚══════════════════════════════════════════════╝"
    )
    for tool_info in registry.list_tools():
        logger.info(
            "  → %s: %s", tool_info["name"], tool_info["description"]
        )

    yield  # Application runs here

    # --- Shutdown ---
    logger.info("MCP Server shutting down gracefully.")


# ============================================================
#  FASTAPI APPLICATION
# ============================================================

# Initialize registry at module load (happens once at container startup)
registry: ToolRegistry = _create_registry()

app = FastAPI(
    title="MCP Server — SysAdmin AI Bot",
    description="Model Context Protocol server for tool execution",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)


# ============================================================
#  RESPONSE MODELS
# ============================================================

class HealthResponse(BaseModel):
    status: str = Field(default="healthy")
    service: str = Field(default="mcp-server")
    tools_registered: int = Field(default=0)


class ToolListResponse(BaseModel):
    tools: list[dict[str, Any]]
    total: int


# ============================================================
#  ENDPOINTS
# ============================================================

@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint for Docker and monitoring."""
    return HealthResponse(
        status="healthy",
        service="mcp-server",
        tools_registered=registry.tool_count,
    )


@app.get("/tools", response_model=ToolListResponse)
async def list_tools() -> ToolListResponse:
    """List all registered tools and their capabilities."""
    tools = registry.list_tools()
    return ToolListResponse(tools=tools, total=len(tools))


@app.post("/execute", response_model=ToolResult)
async def execute_tool(request: ToolRequest) -> ToolResult:
    """
    Execute a tool action.

    This is the primary endpoint called by the Core App.
    The flow is:
      1. Core App validates RBAC permissions
      2. Core App sends ToolRequest here
      3. MCP Server routes to the correct tool
      4. Tool executes and returns ToolResult
      5. Core App presents the result to the user
    """
    logger.info(
        "Received tool request: tool='%s', action='%s', user_role='%s'",
        request.tool_name, request.action, request.user_role,
    )

    # --- Locate the tool ---
    tool = registry.get(request.tool_name)
    if tool is None:
        available = [t["name"] for t in registry.list_tools()]
        logger.warning("Tool not found: '%s'", request.tool_name)
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"Tool '{request.tool_name}' not found.",
                "available_tools": available,
            },
        )

    # --- Validate the action ---
    try:
        tool.validate_action(request.action)
    except ValueError as exc:
        logger.warning("Invalid action: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    # --- Execute ---
    try:
        result = await tool.execute(request.action, request.parameters)
        logger.info(
            "Tool '%s' action '%s' completed: status=%s",
            request.tool_name, request.action, result.status,
        )
        return result
    except Exception as exc:
        logger.exception("Tool execution failed: %s", exc)
        return ToolResult(
            status=ToolResultStatus.ERROR,
            tool_name=request.tool_name,
            action=request.action,
            message=f"Internal tool error: {exc}",
        )
