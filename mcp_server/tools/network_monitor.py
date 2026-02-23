"""
MCP Tool — Network Monitor
============================
Performs network diagnostics: ping, DNS lookup, route checks.
Read-only, safe operations — available to all RBAC roles.

SOLID Principles Applied:
  - S: Only handles network diagnostic operations.
  - O: New network actions can be added without modifying existing ones.
  - L: Fully substitutable as a BaseTool instance.
  - I: Implements only the BaseTool interface.
  - D: Depends on abstractions (BaseTool), not on the server directly.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import shlex
from typing import Any

from mcp_server.tools.base_tool import BaseTool, ToolResult, ToolResultStatus

logger = logging.getLogger(__name__)

# Maximum output size for network commands
_MAX_OUTPUT_LENGTH: int = 10_000
_DEFAULT_TIMEOUT: int = 15


class NetworkMonitorTool(BaseTool):
    """
    Network diagnostic tool for connectivity and health checks.

    All operations are read-only and safe — no state is modified
    on any target system. Available to all RBAC roles.

    Supported Actions:
        ping           — ICMP ping to a host
        dns_lookup     — DNS resolution (nslookup/dig)
        check_routes   — Display local routing table
    """

    @property
    def name(self) -> str:
        return "network_monitor"

    @property
    def description(self) -> str:
        return (
            "Network diagnostics: ping hosts, DNS lookups, "
            "and route table inspection. Read-only and safe."
        )

    @property
    def supported_actions(self) -> list[str]:
        return ["ping", "dns_lookup", "check_routes"]

    async def execute(self, action: str, parameters: dict[str, Any]) -> ToolResult:
        """Route to the appropriate network diagnostic handler."""
        self.validate_action(action)

        handlers = {
            "ping": self._ping,
            "dns_lookup": self._dns_lookup,
            "check_routes": self._check_routes,
        }

        handler = handlers[action]
        return await handler(parameters)

    # --- Private Action Handlers ---

    async def _ping(self, parameters: dict[str, Any]) -> ToolResult:
        """
        Ping a target host.

        Parameters:
            host (str):   Target hostname or IP address.
            count (int):  Number of ping packets (default: 4, max: 10).
        """
        host: str = parameters.get("host", "").strip()
        if not host:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="ping",
                message="No host provided. 'host' parameter is required.",
            )

        # Sanitize: only allow alphanumeric, dots, hyphens, colons (IPv6)
        if not all(c.isalnum() or c in ".-:" for c in host):
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="ping",
                message=f"Invalid host format: '{host}'",
            )

        count = min(int(parameters.get("count", 4)), 10)

        # Platform-aware ping flag (-c for Linux/Mac, -n for Windows)
        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = f"ping {count_flag} {count} {shlex.quote(host)}"

        logger.info("Executing ping: %s", cmd)

        return await self._run_local_command(cmd, "ping")

    async def _dns_lookup(self, parameters: dict[str, Any]) -> ToolResult:
        """
        Perform DNS resolution on a hostname.

        Parameters:
            host (str):        Target hostname.
            record_type (str): DNS record type (default: 'A').
        """
        host: str = parameters.get("host", "").strip()
        if not host:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="dns_lookup",
                message="No host provided. 'host' parameter is required.",
            )

        # Sanitize
        if not all(c.isalnum() or c in ".-" for c in host):
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="dns_lookup",
                message=f"Invalid host format: '{host}'",
            )

        record_type = parameters.get("record_type", "A").upper()
        allowed_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"}
        if record_type not in allowed_types:
            record_type = "A"

        cmd = f"nslookup -type={record_type} {shlex.quote(host)}"

        logger.info("Executing DNS lookup: %s", cmd)

        return await self._run_local_command(cmd, "dns_lookup")

    async def _check_routes(self, parameters: dict[str, Any]) -> ToolResult:
        """Display the local routing table."""
        cmd = "ip route show" if platform.system().lower() == "linux" else "netstat -rn"

        logger.info("Checking routes: %s", cmd)

        return await self._run_local_command(cmd, "check_routes")

    # --- Utility ---

    async def _run_local_command(self, cmd: str, action: str) -> ToolResult:
        """
        Execute a shell command locally inside the MCP container.

        This is used for network diagnostic commands that run
        FROM the MCP container (not via SSH to a remote host).
        """
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=_DEFAULT_TIMEOUT,
            )

            stdout_text = stdout_bytes.decode("utf-8", errors="replace")
            stderr_text = stderr_bytes.decode("utf-8", errors="replace")

            # Truncate if needed
            if len(stdout_text) > _MAX_OUTPUT_LENGTH:
                stdout_text = stdout_text[:_MAX_OUTPUT_LENGTH] + "\n... [TRUNCATED]"

            exit_code = process.returncode or 0
            status = (
                ToolResultStatus.SUCCESS if exit_code == 0
                else ToolResultStatus.ERROR
            )

            return ToolResult(
                status=status,
                tool_name=self.name,
                action=action,
                message=(
                    f"Command completed (exit code: {exit_code})"
                    if exit_code == 0
                    else f"Command failed (exit code: {exit_code})"
                ),
                data={
                    "command": cmd,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "exit_code": exit_code,
                },
            )

        except asyncio.TimeoutError:
            return ToolResult(
                status=ToolResultStatus.TIMEOUT,
                tool_name=self.name,
                action=action,
                message=f"Command timed out after {_DEFAULT_TIMEOUT}s",
                data={"command": cmd},
            )
        except Exception as exc:
            logger.exception("Local command execution failed: %s", exc)
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action=action,
                message=f"Execution error: {exc}",
                data={"command": cmd, "error": str(exc)},
            )
