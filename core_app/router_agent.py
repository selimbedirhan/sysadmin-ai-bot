"""
Router Agent — Dynamic Query Classification & Model Routing
=============================================================
The "brain" of the SysAdmin AI Bot. Routes user queries to the
appropriate model and orchestrates tool execution via MCP.

Flow:
  1. User message arrives
  2. Router Model (3B, fast) classifies: CHAT or SYSADMIN
  3a. CHAT → Chat Model (3B, conversational) responds directly
  3b. SYSADMIN → Expert Model (8B, reasoning) analyzes the request
  4. Expert extracts command → RBAC validates → MCP executes
  5. Expert receives tool output → generates final analysis

Architecture:
  - ConfigLoader:    Reads YAML configs into structured objects.
  - MCPClient:       HTTP client for MCP Server communication.
  - RouterAgent:     Orchestrates the entire query pipeline.

SOLID Principles Applied:
  - S: Each class has a single, well-defined responsibility.
  - O: New model tiers or routing strategies extend, not modify.
  - L: All components are substitutable through their interfaces.
  - I: RouterAgent exposes only process_message() to callers.
  - D: Depends on config abstractions, not hardcoded values.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

logger = logging.getLogger(__name__)


# ============================================================
#  CONFIGURATION LOADER
#  Single Responsibility: Parse YAML files into typed objects.
# ============================================================

@dataclass(frozen=True)
class ModelConfig:
    """Immutable configuration for a single model tier."""
    name: str
    temperature: float
    max_tokens: int
    timeout_seconds: int
    description: str = ""


@dataclass(frozen=True)
class MCPConfig:
    """Immutable MCP Server connection configuration."""
    host: str
    port: int
    base_url: str
    request_timeout_seconds: int
    max_retries: int
    retry_backoff_seconds: int


@dataclass
class AppConfig:
    """Aggregated application configuration from all YAML files."""
    # Models
    router_model: ModelConfig = field(default_factory=lambda: ModelConfig(
        name="llama3.2:3b", temperature=0.1, max_tokens=10, timeout_seconds=15,
    ))
    expert_model: ModelConfig = field(default_factory=lambda: ModelConfig(
        name="llama3.1:8b", temperature=0.3, max_tokens=2048, timeout_seconds=120,
    ))
    chat_model: ModelConfig = field(default_factory=lambda: ModelConfig(
        name="llama3.2:3b", temperature=0.7, max_tokens=512, timeout_seconds=30,
    ))

    # MCP
    mcp: MCPConfig = field(default_factory=lambda: MCPConfig(
        host="mcp-server", port=8100, base_url="http://mcp-server:8100",
        request_timeout_seconds=60, max_retries=3, retry_backoff_seconds=2,
    ))

    # Prompts
    system_prompt: str = ""
    router_prompt: str = ""

    # Identity
    app_name: str = "ATLAS — Turkcell SysAdmin AI"
    version: str = "1.0.0"

    # Fallback responses
    fallback_responses: dict[str, str] = field(default_factory=dict)


class ConfigLoader:
    """
    Loads and merges configuration from multiple YAML files.

    Reads:
      - config/system_settings.yaml  → model params, MCP config
      - config/sysadmin_persona.yaml → prompts, identity, fallbacks
    """

    def __init__(self, config_dir: str | Path = "/app/config") -> None:
        self._config_dir = Path(config_dir)

    def load(self) -> AppConfig:
        """Parse all YAML configs and return a unified AppConfig."""
        settings = self._read_yaml("system_settings.yaml")
        persona = self._read_yaml("sysadmin_persona.yaml")

        config = AppConfig()

        # --- Model Configurations ---
        models = settings.get("models", {})
        if "router" in models:
            config.router_model = self._parse_model(models["router"])
        if "expert" in models:
            config.expert_model = self._parse_model(models["expert"])
        if "chat" in models:
            config.chat_model = self._parse_model(models["chat"])

        # --- MCP Configuration ---
        mcp_raw = settings.get("mcp_server", {})
        if mcp_raw:
            config.mcp = MCPConfig(
                host=mcp_raw.get("host", "mcp-server"),
                port=mcp_raw.get("port", 8100),
                base_url=mcp_raw.get("base_url", "http://mcp-server:8100"),
                request_timeout_seconds=mcp_raw.get("request_timeout_seconds", 60),
                max_retries=mcp_raw.get("max_retries", 3),
                retry_backoff_seconds=mcp_raw.get("retry_backoff_seconds", 2),
            )

        # --- Prompts & Identity ---
        config.system_prompt = persona.get("system_prompt", "")
        config.router_prompt = persona.get("router_prompt", "")
        config.fallback_responses = persona.get("fallback_responses", {})

        identity = persona.get("identity", {})
        app_settings = settings.get("application", {})
        config.app_name = app_settings.get("name", identity.get("name", config.app_name))
        config.version = app_settings.get("version", identity.get("version", config.version))

        logger.info(
            "Configuration loaded: router=%s, expert=%s, chat=%s",
            config.router_model.name, config.expert_model.name, config.chat_model.name,
        )

        return config

    def _read_yaml(self, filename: str) -> dict[str, Any]:
        """Read and parse a single YAML file."""
        filepath = self._config_dir / filename
        if not filepath.exists():
            logger.warning("Config file not found: %s", filepath)
            return {}

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return data if isinstance(data, dict) else {}

    @staticmethod
    def _parse_model(raw: dict[str, Any]) -> ModelConfig:
        """Parse a raw model dict into a ModelConfig."""
        return ModelConfig(
            name=raw.get("name", "llama3.2:3b"),
            temperature=float(raw.get("temperature", 0.5)),
            max_tokens=int(raw.get("max_tokens", 512)),
            timeout_seconds=int(raw.get("timeout_seconds", 30)),
            description=raw.get("description", ""),
        )


# ============================================================
#  MCP CLIENT
#  Single Responsibility: HTTP communication with MCP Server.
# ============================================================

class MCPClient:
    """
    HTTP client for the MCP (Model Context Protocol) Server.

    Sends tool execution requests and receives standardized results.
    Handles retries, timeouts, and connection failures gracefully.
    """

    def __init__(self, config: MCPConfig) -> None:
        self._config = config
        self._base_url = config.base_url
        self._timeout = config.request_timeout_seconds
        self._max_retries = config.max_retries
        self._backoff = config.retry_backoff_seconds

    async def execute_tool(
        self,
        tool_name: str,
        action: str,
        parameters: dict[str, Any],
        user_role: str = "junior",
    ) -> dict[str, Any]:
        """
        Send a tool execution request to the MCP Server.

        Args:
            tool_name:  Name of the tool (e.g., 'linux_ssh').
            action:     Specific action (e.g., 'execute_command').
            parameters: Action-specific arguments.
            user_role:  RBAC role of the requesting user.

        Returns:
            Parsed ToolResult as a dictionary.

        Raises:
            MCPConnectionError: If the MCP Server is unreachable.
        """
        payload = {
            "tool_name": tool_name,
            "action": action,
            "parameters": parameters,
            "user_role": user_role,
        }

        logger.info(
            "MCP request: tool='%s', action='%s', params=%s",
            tool_name, action, parameters,
        )

        last_error: Exception | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.post(
                        f"{self._base_url}/execute",
                        json=payload,
                    )
                    response.raise_for_status()
                    result = response.json()

                    logger.info(
                        "MCP response: status='%s', message='%s'",
                        result.get("status"), result.get("message"),
                    )
                    return result

            except httpx.ConnectError as exc:
                last_error = exc
                logger.warning(
                    "MCP connection failed (attempt %d/%d): %s",
                    attempt, self._max_retries, exc,
                )
            except httpx.HTTPStatusError as exc:
                last_error = exc
                logger.error("MCP HTTP error: %s", exc)
                # Don't retry on 4xx errors
                if 400 <= exc.response.status_code < 500:
                    break
            except Exception as exc:
                last_error = exc
                logger.exception("MCP request failed: %s", exc)

            # Exponential backoff between retries
            if attempt < self._max_retries:
                await asyncio.sleep(self._backoff * attempt)

        # All retries exhausted
        error_msg = str(last_error) if last_error else "Unknown error"
        return {
            "status": "error",
            "tool_name": tool_name,
            "action": action,
            "message": f"MCP Server unreachable after {self._max_retries} attempts: {error_msg}",
            "data": {},
        }

    async def health_check(self) -> bool:
        """Check if the MCP Server is reachable and healthy."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self._base_url}/health")
                return response.status_code == 200
        except Exception:
            return False

    async def list_tools(self) -> list[dict[str, Any]]:
        """Retrieve the list of available tools from MCP Server."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self._base_url}/tools")
                response.raise_for_status()
                data = response.json()
                return data.get("tools", [])
        except Exception as exc:
            logger.error("Failed to list MCP tools: %s", exc)
            return []


# ============================================================
#  QUERY CLASSIFICATION
# ============================================================

class QueryClassification:
    """Result of classifying a user query."""
    CHAT = "CHAT"
    SYSADMIN = "SYSADMIN"


# ============================================================
#  COMMAND EXTRACTION PATTERNS
# ============================================================

# Patterns to extract actionable commands from the Expert model's response
_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"```(?:bash|sh|shell)?\s*\n(.+?)\n```", re.DOTALL),
    re.compile(r"`([^`]+)`"),
    re.compile(r"Command:\s*(.+)$", re.MULTILINE),
    re.compile(r"Run:\s*(.+)$", re.MULTILINE),
]


# ============================================================
#  ROUTER AGENT
#  The orchestrator: classifies, routes, validates, executes.
# ============================================================

class RouterAgent:
    """
    Central orchestrator for the SysAdmin AI Bot.

    Process flow:
      1. Classify query via Router Model (3B)
      2. Route to Chat Model (3B) or Expert Model (8B)
      3. If sysadmin: extract command → RBAC check → MCP execute
      4. Feed tool output back to Expert for analysis
      5. Return final response to user

    Thread Safety:
      This class is designed to be instantiated ONCE and shared.
      All methods are async and stateless per-request.
    """

    def __init__(
        self,
        config: AppConfig,
        rbac_manager: Any,  # RBACSecurityManager — imported at runtime to avoid circular deps
        ollama_base_url: str = "http://ollama-engine:11434",
    ) -> None:
        self._config = config
        self._rbac = rbac_manager
        self._ollama_base_url = ollama_base_url

        # --- Initialize LangChain models ---
        self._router_llm = ChatOllama(
            model=config.router_model.name,
            base_url=ollama_base_url,
            temperature=config.router_model.temperature,
            num_predict=config.router_model.max_tokens,
        )

        self._expert_llm = ChatOllama(
            model=config.expert_model.name,
            base_url=ollama_base_url,
            temperature=config.expert_model.temperature,
            num_predict=config.expert_model.max_tokens,
        )

        self._chat_llm = ChatOllama(
            model=config.chat_model.name,
            base_url=ollama_base_url,
            temperature=config.chat_model.temperature,
            num_predict=config.chat_model.max_tokens,
        )

        # --- Initialize MCP Client ---
        self._mcp = MCPClient(config.mcp)

        # --- Conversation history (per-session, managed by main.py) ---
        self._conversation_history: list[HumanMessage | AIMessage] = []
        self._command_count: int = 0

        logger.info("RouterAgent initialized with models: router=%s, expert=%s, chat=%s",
                     config.router_model.name, config.expert_model.name, config.chat_model.name)

    # --- Public Interface ---

    async def process_message(
        self,
        user_message: str,
        username: str = "turkcell_junior",
    ) -> str:
        """
        Process a user message through the full routing pipeline.

        This is the SINGLE entry point for all user interactions.

        Args:
            user_message: The raw user input.
            username:     Authenticated username for RBAC.

        Returns:
            The AI's response string.
        """
        logger.info("Processing message from '%s': '%s'", username, user_message[:100])

        # Step 1: Classify the query
        classification = await self._classify_query(user_message)
        logger.info("Query classified as: %s", classification)

        # Step 2: Route based on classification
        if classification == QueryClassification.CHAT:
            response = await self._handle_chat(user_message)
        else:
            response = await self._handle_sysadmin(user_message, username)

        # Step 3: Update conversation history
        self._conversation_history.append(HumanMessage(content=user_message))
        self._conversation_history.append(AIMessage(content=response))

        # Keep history manageable (last 20 messages = 10 exchanges)
        if len(self._conversation_history) > 20:
            self._conversation_history = self._conversation_history[-20:]

        return response

    async def check_mcp_health(self) -> bool:
        """Check MCP Server connectivity."""
        return await self._mcp.health_check()

    def clear_history(self) -> None:
        """Reset conversation history for a new session."""
        self._conversation_history.clear()
        logger.info("Conversation history cleared.")

    @property
    def conversation_history_count(self) -> int:
        """Number of messages in conversation history."""
        return len(self._conversation_history)

    # --- Private: Query Classification ---

    async def _classify_query(self, user_message: str) -> str:
        """
        Use the Router Model (3B) to classify a query as CHAT or SYSADMIN.

        Uses a fast keyword pre-check before the LLM call to short-circuit
        obvious cases and improve response time.
        Falls back to CHAT if classification fails.
        """
        normalized = user_message.strip().lower()

        # --- Fast path: obvious CHAT (skip LLM entirely) ---
        chat_phrases = (
            "hello", "hi", "hey", "merhaba", "selam", "nasılsın",
            "who are you", "what can you do", "what are you",
            "help me", "thank", "thanks", "bye", "goodbye",
            "tell me about yourself", "how are you",
            "what is your name", "your name",
        )
        if any(normalized.startswith(p) or normalized == p for p in chat_phrases):
            logger.info("Fast-path classification: CHAT (keyword match)")
            return QueryClassification.CHAT

        # --- Fast path: obvious SYSADMIN keywords ---
        sysadmin_keywords = (
            "ping ", "nslookup ", "dig ", "traceroute ",
            "df ", "du ", "top", "htop", "ps ", "free",
            "systemctl ", "service ", "journalctl",
            "cat /", "tail ", "grep ", "ls /", "find /",
            "uptime", "uname", "hostname", "whoami",
            "netstat", "ss ", "ip addr", "ip route",
            "iptables", "firewall", "chmod ", "chown ",
            "apt ", "yum ", "dnf ", "rpm ",
            "disk", "memory", "cpu", "process",
            "check ", "show ", "restart ", "stop ", "start ",
        )
        if any(kw in normalized for kw in sysadmin_keywords):
            logger.info("Fast-path classification: SYSADMIN (keyword match)")
            return QueryClassification.SYSADMIN

        # --- Slow path: LLM classification ---
        try:
            messages = [
                SystemMessage(content=self._config.router_prompt),
                HumanMessage(content=user_message),
            ]

            response = await self._router_llm.ainvoke(messages)
            classification = response.content.strip().upper()
            logger.info("LLM classification raw response: '%s'", classification)

            # Extract just the classification word
            if "SYSADMIN" in classification:
                return QueryClassification.SYSADMIN
            else:
                return QueryClassification.CHAT

        except Exception as exc:
            logger.error("Classification failed, defaulting to CHAT: %s", exc)
            return QueryClassification.CHAT

    # --- Private: Chat Handler ---

    async def _handle_chat(self, user_message: str) -> str:
        """
        Handle general conversation via the Chat Model (3B).

        Lightweight, conversational — no tools needed.
        """
        try:
            messages = [
                SystemMessage(content=(
                    "You are TAO (Turkcell Ajan-Ops), Senior System Administrator and "
                    "Security Architect at Turkcell. CCIE and RHCA certified. "
                    "You are having a general conversation right now, but your tone must remain "
                    "cold, professional, analytical, and highly technical at all times. "
                    "Never use emojis or casual greetings. "
                    "Always respond in the language the user speaks. "
                    "If asked about your capabilities, mention SSH execution, network monitoring, "
                    "system health diagnostics, and Zero Trust compliance."
                )),
                *self._conversation_history[-10:],
                HumanMessage(content=user_message),
            ]

            response = await self._chat_llm.ainvoke(messages)
            return response.content

        except Exception as exc:
            logger.error("Chat handler failed: %s", exc)
            return f"❌ I encountered an error processing your message: {exc}"

    # --- Private: SysAdmin Handler ---

    async def _handle_sysadmin(self, user_message: str, username: str) -> str:
        """
        Handle sysadmin tasks via the Expert Model.

        Two paths:
          A. Direct command (user typed something like "ping 8.8.8.8")
             → Skip expert Phase 1, go straight to RBAC → MCP → analysis
          B. Ambiguous request (user typed "check if google is reachable")
             → Expert proposes a command → extract → RBAC → MCP → analysis
        """
        try:
            # --- Rate Limiting ---
            max_commands = self._rbac.max_commands_per_session
            if self._command_count >= max_commands:
                return (
                    f"⛔ Rate limit reached: {max_commands} commands per session. "
                    f"Please start a new session or contact an administrator."
                )

            # --- Try direct command extraction from user input ---
            direct_command = self._extract_command(f"```\n{user_message}\n```")
            if not direct_command:
                # Check if user input itself looks like a command
                normalized = user_message.strip().lower()
                cmd_prefixes = (
                    "ping ", "nslookup ", "dig ", "traceroute ",
                    "df ", "du ", "top", "htop", "ps ", "free",
                    "systemctl ", "service ", "journalctl",
                    "cat ", "tail ", "grep ", "ls ", "find ",
                    "uptime", "uname", "hostname",
                    "netstat", "ss ", "ip addr", "ip route", "route",
                    "iptables", "chmod ", "chown ",
                    "apt ", "yum ", "dnf ",
                )
                if any(normalized.startswith(p) or normalized == p.strip() for p in cmd_prefixes):
                    direct_command = user_message.strip()

            if direct_command:
                # === PATH A: Direct command — skip expert Phase 1 ===
                command = direct_command
                tool_name, action, parameters = self._classify_tool_and_action(command)
            else:
                # === PATH B: Ambiguous — ask expert to propose a command ===
                tool_instruction = (
                    "Analyze the user's request and propose the exact Linux command "
                    "to execute. Put the command in a ```bash code block. "
                    "Briefly explain what it does and its safety level."
                )

                expert_messages = [
                    SystemMessage(content=self._config.system_prompt),
                    HumanMessage(content=user_message),
                    SystemMessage(content=tool_instruction),
                ]

                expert_response = await self._expert_llm.ainvoke(expert_messages)
                expert_text = expert_response.content
                logger.info(
                    "Expert response length: %d chars, preview: '%.100s'",
                    len(expert_text) if expert_text else 0,
                    expert_text[:100] if expert_text else "<EMPTY>",
                )

                # Guard: empty expert response → fallback to chat
                if not expert_text or not expert_text.strip():
                    logger.warning(
                        "Expert returned empty response, falling back to chat handler."
                    )
                    return await self._handle_chat(user_message)

                command = self._extract_command(expert_text)
                if not command:
                    return expert_text

                tool_name, action, parameters = self._classify_tool_and_action(command)

            # --- RBAC Validation ---
            from core_app.rbac_security import PermissionStatus

            rbac_action = {
                "linux_ssh": "ssh_execute",
                "network_monitor": "network_diagnostics",
            }.get(tool_name, "ssh_execute")

            verdict = self._rbac.check_permission(
                username=username,
                action=rbac_action,
                command=command,
            )

            if verdict.status == PermissionStatus.DENIED:
                return verdict.message

            if verdict.status == PermissionStatus.REQUIRES_CONFIRMATION:
                return (
                    f"⚠️ **Onay Gerekli** (Güvenlik: {verdict.safety_level.value})\n"
                    f"Komut: `{command}`\n"
                    f"Rol: {verdict.user_role}\n\n"
                    f"Devam etmek için **'yes'** veya iptal için **'no'** yazın."
                )

            # --- Execute via MCP ---
            self._command_count += 1
            tool_result = await self._mcp.execute_tool(
                tool_name=tool_name,
                action=action,
                parameters=parameters,
                user_role=verdict.user_role,
            )

            # --- Expert analyzes the output ---
            output_text = self._format_tool_result(tool_result)

            analysis_messages = [
                SystemMessage(content=self._config.system_prompt),
                HumanMessage(content=(
                    f"Kullanıcı isteği: {user_message}\n"
                    f"Çalıştırılan komut: `{command}` ({tool_name})\n\n"
                    f"Komut çıktısı:\n{output_text}\n\n"
                    f"Yukarıdaki gerçek verileri kullanarak [TESPİT], [ANALİZ], "
                    f"[AKSİYON PLANI] formatında analiz yap. "
                    f"Veri yoksa veya hata varsa bunu açıkça belirt."
                )),
            ]

            analysis_response = await self._expert_llm.ainvoke(analysis_messages)
            return analysis_response.content

        except Exception as exc:
            logger.exception("SysAdmin handler failed: %s", exc)
            return f"[HATA]: İstek işlenirken bir hata oluştu: {exc}"

    # --- Private: Tool Classification ---

    @staticmethod
    def _classify_tool_and_action(command: str) -> tuple[str, str, dict[str, Any]]:
        """
        Determine which MCP tool and action to use for a command.

        Inspects the command string to route to:
          - network_monitor/ping for ping commands
          - network_monitor/dns_lookup for nslookup/dig commands
          - network_monitor/check_routes for route commands
          - linux_ssh/execute_command for everything else

        Returns:
            (tool_name, action, parameters)
        """
        normalized = command.strip().lower()

        # --- Network Monitor: Ping ---
        ping_match = re.match(r"^ping\s+(?:-\w+\s+\d+\s+)?(.+)$", normalized)
        if ping_match:
            host = ping_match.group(1).strip()
            count_match = re.search(r"-c\s+(\d+)", normalized)
            count = int(count_match.group(1)) if count_match else 4
            return ("network_monitor", "ping", {"host": host, "count": count})

        # --- Network Monitor: DNS Lookup ---
        dns_match = re.match(r"^(?:nslookup|dig)\s+(.+)$", normalized)
        if dns_match:
            host = dns_match.group(1).strip()
            return ("network_monitor", "dns_lookup", {"host": host})

        # --- Network Monitor: Routes ---
        if normalized in ("route", "ip route", "ip route show", "netstat -rn"):
            return ("network_monitor", "check_routes", {})

        # --- Default: SSH ---
        return ("linux_ssh", "execute_command", {
            "command": command,
            "host": os.environ.get("SSH_TARGET_HOST", ""),
            "port": int(os.environ.get("SSH_TARGET_PORT", "22")),
            "user": os.environ.get("SSH_TARGET_USER", "admin"),
        })

    # --- Private: Pending Confirmation Handler ---

    async def handle_confirmation(
        self,
        confirmed: bool,
        command: str,
        username: str,
        original_analysis: str,
    ) -> str:
        """
        Handle a user's yes/no response to a confirmation request.

        Called by main.py when the user responds to a ⚠️ prompt.
        """
        if not confirmed:
            return "❌ Command execution cancelled by user."

        user_role = self._rbac.get_user_role(username)

        # Use the same tool classification as _handle_sysadmin
        tool_name, action, parameters = self._classify_tool_and_action(command)
        self._command_count += 1

        # Execute via MCP
        tool_result = await self._mcp.execute_tool(
            tool_name=tool_name,
            action=action,
            parameters=parameters,
            user_role=user_role,
        )

        output_text = self._format_tool_result(tool_result)

        # Expert analysis of the output
        analysis_messages = [
            SystemMessage(content=self._config.system_prompt),
            AIMessage(content=original_analysis),
            HumanMessage(content=(
                f"The user confirmed execution. Command `{command}` "
                f"has been executed. Output:\n\n{output_text}\n\n"
                f"Please analyze the result."
            )),
        ]

        try:
            analysis_response = await self._expert_llm.ainvoke(analysis_messages)
            return analysis_response.content
        except Exception as exc:
            logger.error("Post-confirmation analysis failed: %s", exc)
            return f"Command executed. Raw output:\n\n{output_text}"

    # --- Private: Utility Methods ---

    @staticmethod
    def _extract_command(text: str) -> str:
        """
        Extract a shell command from the Expert model's response.

        Looks for commands in code blocks (```bash ... ```) first,
        then falls back to inline code (`...`) and keyword patterns.

        Returns:
            The first extracted command, or empty string if none found.
        """
        for pattern in _COMMAND_PATTERNS:
            match = pattern.search(text)
            if match:
                command = match.group(1).strip()
                # Skip commands that are clearly explanatory, not executable
                if command and not command.startswith("#") and len(command) < 500:
                    return command

        return ""

    @staticmethod
    def _format_tool_result(result: dict[str, Any]) -> str:
        """Format a MCP ToolResult dict into a human-readable string."""
        status = result.get("status", "unknown")
        message = result.get("message", "")
        data = result.get("data", {})

        parts: list[str] = []

        parts.append(f"**Status**: {status}")
        if message:
            parts.append(f"**Message**: {message}")

        stdout = data.get("stdout", "")
        stderr = data.get("stderr", "")
        exit_code = data.get("exit_code")

        if exit_code is not None:
            parts.append(f"**Exit Code**: {exit_code}")

        if stdout:
            parts.append(f"**Output**:\n```\n{stdout}\n```")

        if stderr:
            parts.append(f"**Errors**:\n```\n{stderr}\n```")

        return "\n".join(parts)
