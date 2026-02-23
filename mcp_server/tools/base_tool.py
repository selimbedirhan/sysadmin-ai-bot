"""
MCP Server — Tool Base Abstraction
===================================
Defines the interface contract that ALL tools must implement.
Follows the Open/Closed Principle: new tools extend BaseTool
without modifying existing code.

SOLID Principles Applied:
  - S: Each tool has a Single Responsibility
  - O: Open for extension (new tools), Closed for modification
  - L: All tools are substitutable via BaseTool interface
  - I: Minimal interface — only what's needed
  - D: Server depends on BaseTool abstraction, not concrete tools
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ============================================================
#  DATA MODELS — Shared across all tools
# ============================================================

class ToolResultStatus(str, Enum):
    """Outcome status of a tool execution."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"


class ToolRequest(BaseModel):
    """
    Incoming request to execute a tool.

    Attributes:
        tool_name:  Identifier of the tool to invoke.
        action:     Specific action within the tool (e.g., 'execute_command').
        parameters: Action-specific key-value arguments.
        user_role:  RBAC role of the requesting user (injected by Core App).
    """
    tool_name: str = Field(..., description="Name of the tool to invoke")
    action: str = Field(..., description="Specific action to perform")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters",
    )
    user_role: str = Field(
        default="junior",
        description="RBAC role of the requesting user",
    )


class ToolResult(BaseModel):
    """
    Standardized response from any tool execution.

    Every tool returns this exact shape — the Core App never
    needs to know which tool produced the result.
    """
    status: ToolResultStatus = Field(..., description="Execution outcome")
    tool_name: str = Field(..., description="Tool that produced this result")
    action: str = Field(..., description="Action that was executed")
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Result payload (output, metrics, etc.)",
    )
    message: str = Field(default="", description="Human-readable summary")


# ============================================================
#  ABSTRACT BASE CLASS — The Tool Contract
# ============================================================

class BaseTool(ABC):
    """
    Abstract base for all MCP tools.

    Every tool must:
      1. Declare a unique `name` property.
      2. Declare a human-readable `description`.
      3. List its supported `actions`.
      4. Implement `execute()` to handle any supported action.

    The MCP Server discovers tools at startup and routes
    requests by matching `tool_name` → `BaseTool.name`.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this tool (e.g., 'linux_ssh')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the tool's purpose."""
        ...

    @property
    @abstractmethod
    def supported_actions(self) -> list[str]:
        """List of action strings this tool can handle."""
        ...

    @abstractmethod
    async def execute(self, action: str, parameters: dict[str, Any]) -> ToolResult:
        """
        Execute the given action with the provided parameters.

        Args:
            action:     One of `self.supported_actions`.
            parameters: Action-specific arguments.

        Returns:
            ToolResult with status, data, and message.

        Raises:
            ValueError: If action is not in `supported_actions`.
        """
        ...

    def validate_action(self, action: str) -> None:
        """Guard: raises ValueError if action is unsupported."""
        if action not in self.supported_actions:
            raise ValueError(
                f"Tool '{self.name}' does not support action '{action}'. "
                f"Supported: {self.supported_actions}"
            )
