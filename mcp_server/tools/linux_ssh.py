"""
MCP Tool — Linux SSH Executor
==============================
Connects to target Linux servers via SSH and executes commands.
This is the primary "arm" of the SysAdmin AI Bot.

SOLID Principles Applied:
  - S: Only handles SSH command execution — nothing else.
  - O: New SSH-related actions can be added without modifying existing ones.
  - L: Fully substitutable as a BaseTool instance.
  - I: Implements only the BaseTool interface.
  - D: Depends on abstractions (BaseTool), not on the server directly.

Security:
  - Command blocklist validation happens here as a LAST line of defense.
  - Primary RBAC checks happen in the Core App BEFORE reaching this tool.
  - Output is truncated to prevent memory exhaustion from verbose commands.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import paramiko

from mcp_server.tools.base_tool import BaseTool, ToolResult, ToolResultStatus

logger = logging.getLogger(__name__)


# ============================================================
#  CONFIGURATION CONSTANTS
# ============================================================

# Commands that are ALWAYS blocked — last line of defense
_GLOBAL_BLOCKED_COMMANDS: frozenset[str] = frozenset({
    "rm -rf /",
    "rm -rf /*",
    ":(){ :|:& };:",
    "> /dev/sda",
    "mkfs /dev/sda",
    "dd if=/dev/zero of=/dev/sda",
    "chmod -R 777 /",
})

# Maximum output size to prevent memory exhaustion (in characters)
_MAX_OUTPUT_LENGTH: int = 50_000

# Maximum lines to return
_MAX_OUTPUT_LINES: int = 500

# Default command execution timeout (seconds)
_DEFAULT_COMMAND_TIMEOUT: int = 30


# ============================================================
#  SSH TOOL IMPLEMENTATION
# ============================================================

class LinuxSSHTool(BaseTool):
    """
    Executes commands on remote Linux servers via SSH.

    Uses Paramiko for SSH connectivity with key-based authentication.
    All connections are opened per-request and closed after execution
    to avoid stale connections in a containerized environment.

    Attributes:
        _host:    Target server hostname/IP (from env or parameter).
        _port:    SSH port (default 22).
        _user:    SSH username (from env or parameter).
        _key_path: Path to SSH private key file.
    """

    def __init__(self) -> None:
        self._host: str = os.environ.get("SSH_TARGET_HOST", "")
        self._port: int = int(os.environ.get("SSH_TARGET_PORT", "22"))
        self._user: str = os.environ.get("SSH_TARGET_USER", "admin")
        self._key_path: str = os.environ.get("SSH_KEY_PATH", "/root/.ssh/id_rsa")

    # --- BaseTool Interface Implementation ---

    @property
    def name(self) -> str:
        return "linux_ssh"

    @property
    def description(self) -> str:
        return (
            "Executes shell commands on target Linux servers via SSH. "
            "Supports command execution, file reading, and connection testing."
        )

    @property
    def supported_actions(self) -> list[str]:
        return ["execute_command", "test_connection"]

    async def execute(self, action: str, parameters: dict[str, Any]) -> ToolResult:
        """
        Route to the appropriate handler based on action.

        Args:
            action:     'execute_command' or 'test_connection'.
            parameters: Action-specific arguments.

        Returns:
            Standardized ToolResult.
        """
        self.validate_action(action)

        if action == "execute_command":
            return await self._execute_command(parameters)
        elif action == "test_connection":
            return await self._test_connection(parameters)

        # Unreachable due to validate_action, but explicit for clarity
        return ToolResult(
            status=ToolResultStatus.ERROR,
            tool_name=self.name,
            action=action,
            message=f"Unknown action: {action}",
        )

    # --- Private Action Handlers ---

    async def _execute_command(self, parameters: dict[str, Any]) -> ToolResult:
        """
        Execute a shell command on the target server.

        Parameters:
            command (str):  The shell command to execute.
            host (str):     Optional override for target host.
            port (int):     Optional override for SSH port.
            user (str):     Optional override for SSH user.
            timeout (int):  Command timeout in seconds.

        Returns:
            ToolResult with stdout, stderr, and exit_code in data.
        """
        command: str = parameters.get("command", "").strip()
        if not command:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="execute_command",
                message="No command provided. 'command' parameter is required.",
            )

        # --- Safety: Block globally prohibited commands ---
        if self._is_blocked_command(command):
            logger.warning("BLOCKED dangerous command attempt: %s", command)
            return ToolResult(
                status=ToolResultStatus.PERMISSION_DENIED,
                tool_name=self.name,
                action="execute_command",
                message=f"⛔ Command blocked by safety system: '{command}'",
                data={"command": command, "blocked": True},
            )

        # --- Resolve connection parameters ---
        host = parameters.get("host", self._host)
        port = int(parameters.get("port", self._port))
        user = parameters.get("user", self._user)
        timeout = int(parameters.get("timeout", _DEFAULT_COMMAND_TIMEOUT))

        if not host:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="execute_command",
                message="No target host configured. Set SSH_TARGET_HOST or pass 'host' parameter.",
            )

        logger.info(
            "Executing SSH command on %s@%s:%d — '%s' (timeout=%ds)",
            user, host, port, command, timeout,
        )

        # --- Execute via SSH in a thread (Paramiko is synchronous) ---
        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self._ssh_execute, host, port, user, command, timeout
                ),
                timeout=timeout + 10,  # Extra buffer for connection setup
            )
            return result
        except asyncio.TimeoutError:
            logger.error("SSH command timed out after %ds: %s", timeout, command)
            return ToolResult(
                status=ToolResultStatus.TIMEOUT,
                tool_name=self.name,
                action="execute_command",
                message=f"Command timed out after {timeout}s: '{command}'",
                data={"command": command, "timeout_seconds": timeout},
            )
        except Exception as exc:
            logger.exception("SSH execution failed: %s", exc)
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="execute_command",
                message=f"SSH execution error: {exc}",
                data={"command": command, "error": str(exc)},
            )

    async def _test_connection(self, parameters: dict[str, Any]) -> ToolResult:
        """
        Test SSH connectivity to the target server.

        Parameters:
            host (str): Optional override for target host.
            port (int): Optional override for SSH port.
            user (str): Optional override for SSH user.
        """
        host = parameters.get("host", self._host)
        port = int(parameters.get("port", self._port))
        user = parameters.get("user", self._user)

        if not host:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="test_connection",
                message="No target host configured.",
            )

        logger.info("Testing SSH connection to %s@%s:%d", user, host, port)

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._ssh_test, host, port, user
            )
            return result
        except Exception as exc:
            logger.exception("SSH connection test failed: %s", exc)
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="test_connection",
                message=f"Connection test failed: {exc}",
                data={"host": host, "port": port, "error": str(exc)},
            )

    # --- Synchronous SSH Helpers (run in executor) ---

    def _ssh_execute(
        self, host: str, port: int, user: str, command: str, timeout: int
    ) -> ToolResult:
        """Synchronous SSH command execution via Paramiko."""
        client = paramiko.SSHClient()
        # WarningPolicy logs unknown host keys instead of silently accepting them.
        # In production, use RejectPolicy + managed known_hosts file.
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        try:
            # Connect with key-based authentication
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": user,
                "timeout": 10,
            }
            if os.path.exists(self._key_path):
                connect_kwargs["key_filename"] = self._key_path
            else:
                logger.warning(
                    "SSH key not found at %s — falling back to agent auth",
                    self._key_path,
                )

            client.connect(**connect_kwargs)

            # Execute the command
            _, stdout, stderr = client.exec_command(command, timeout=timeout)

            exit_code: int = stdout.channel.recv_exit_status()
            stdout_text: str = stdout.read().decode("utf-8", errors="replace")
            stderr_text: str = stderr.read().decode("utf-8", errors="replace")

            # Truncate excessive output
            stdout_text = self._truncate_output(stdout_text)
            stderr_text = self._truncate_output(stderr_text)

            status = (
                ToolResultStatus.SUCCESS if exit_code == 0
                else ToolResultStatus.ERROR
            )

            return ToolResult(
                status=status,
                tool_name=self.name,
                action="execute_command",
                message=(
                    f"Command executed successfully (exit code: {exit_code})"
                    if exit_code == 0
                    else f"Command failed with exit code: {exit_code}"
                ),
                data={
                    "command": command,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "exit_code": exit_code,
                    "host": host,
                },
            )

        finally:
            client.close()

    def _ssh_test(self, host: str, port: int, user: str) -> ToolResult:
        """Synchronous SSH connection test via Paramiko."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        try:
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": user,
                "timeout": 10,
            }
            if os.path.exists(self._key_path):
                connect_kwargs["key_filename"] = self._key_path

            client.connect(**connect_kwargs)
            transport = client.get_transport()
            is_active = transport.is_active() if transport else False

            return ToolResult(
                status=ToolResultStatus.SUCCESS,
                tool_name=self.name,
                action="test_connection",
                message=f"✅ SSH connection to {user}@{host}:{port} successful.",
                data={
                    "host": host,
                    "port": port,
                    "user": user,
                    "connected": True,
                    "transport_active": is_active,
                },
            )

        except paramiko.AuthenticationException as exc:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="test_connection",
                message=f"❌ Authentication failed for {user}@{host}:{port}",
                data={"host": host, "error": str(exc), "connected": False},
            )
        except paramiko.SSHException as exc:
            return ToolResult(
                status=ToolResultStatus.ERROR,
                tool_name=self.name,
                action="test_connection",
                message=f"❌ SSH error connecting to {host}:{port}: {exc}",
                data={"host": host, "error": str(exc), "connected": False},
            )
        finally:
            client.close()

    # --- Utility Methods ---

    @staticmethod
    def _is_blocked_command(command: str) -> bool:
        """
        Check if a command matches any globally blocked pattern.

        This is a LAST LINE OF DEFENSE. Primary checks happen in
        the Core App's RBAC module before the request reaches here.
        """
        normalized = command.strip().lower()
        for blocked in _GLOBAL_BLOCKED_COMMANDS:
            if blocked.lower() in normalized:
                return True
        return False

    @staticmethod
    def _truncate_output(text: str) -> str:
        """Truncate output to prevent memory exhaustion."""
        if len(text) > _MAX_OUTPUT_LENGTH:
            lines = text[:_MAX_OUTPUT_LENGTH].splitlines()
            return "\n".join(lines) + f"\n\n... [OUTPUT TRUNCATED — exceeded {_MAX_OUTPUT_LENGTH} chars]"

        lines = text.splitlines()
        if len(lines) > _MAX_OUTPUT_LINES:
            return "\n".join(lines[:_MAX_OUTPUT_LINES]) + f"\n\n... [OUTPUT TRUNCATED — exceeded {_MAX_OUTPUT_LINES} lines]"

        return text
