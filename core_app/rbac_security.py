"""
RBAC Security Module
=====================
Parses config/rbac_roles.yaml and acts as the security gate
for every user request before it reaches the MCP Server.

This module answers three critical questions for every request:
  1. IS the user allowed to perform this action?
  2. DOES the command contain blocked patterns?
  3. DOES this action require explicit confirmation?

Architecture:
  - Loaded ONCE at startup, cached in memory.
  - Called by the Router Agent before every tool invocation.
  - Returns a SecurityVerdict (dataclass) — never raises exceptions.

SOLID Principles Applied:
  - S: Only handles permission checking — no execution, no routing.
  - O: New safety levels and roles are added in YAML, not in code.
  - L: SecurityVerdict is a stable, substitutable contract.
  - I: Exposes only check_permission() and get_user_role() to callers.
  - D: Depends on YAML config (data), not on concrete tool implementations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ============================================================
#  CONSTANTS
# ============================================================

_SAFETY_LEVEL_HIERARCHY: dict[str, int] = {
    "safe": 0,       # 🟢
    "caution": 1,    # 🟡
    "dangerous": 2,  # 🔴
}


# ============================================================
#  DATA MODELS
# ============================================================

class SafetyLevel(str, Enum):
    """Safety classification for an action or command."""
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    DYNAMIC = "dynamic"  # Determined at runtime by command analysis


class PermissionStatus(str, Enum):
    """Outcome of a permission check."""
    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_CONFIRMATION = "requires_confirmation"


@dataclass(frozen=True)
class SecurityVerdict:
    """
    Immutable result of a permission check.

    The Router Agent reads this verdict and decides whether to:
      - Proceed with tool execution (ALLOWED)
      - Ask the user for confirmation (REQUIRES_CONFIRMATION)
      - Reject the request entirely (DENIED)

    Attributes:
        status:          Permission outcome.
        user_role:       Role of the requesting user.
        action:          The action category being checked.
        safety_level:    Determined safety tier.
        message:         Human-readable explanation.
        denied_reason:   Specific reason if denied (empty otherwise).
        matched_blocked: The blocked command pattern that matched (if any).
    """
    status: PermissionStatus
    user_role: str
    action: str
    safety_level: SafetyLevel
    message: str = ""
    denied_reason: str = ""
    matched_blocked: str = ""


@dataclass
class RoleConfig:
    """Parsed representation of a single RBAC role."""
    name: str
    description: str
    allowed_actions: list[str] = field(default_factory=list)
    denied_commands: list[str] = field(default_factory=list)
    max_safety_level: str = "safe"
    requires_confirmation: list[str] = field(default_factory=list)


@dataclass
class UserConfig:
    """Parsed representation of a registered user."""
    username: str
    role: str
    full_name: str = ""
    department: str = ""


# ============================================================
#  RBAC SECURITY MANAGER
# ============================================================

class RBACSecurityManager:
    """
    Central security gate for the SysAdmin AI Bot.

    Loads RBAC configuration from YAML at initialization and
    provides fast, in-memory permission checks for every request.

    Usage:
        manager = RBACSecurityManager("/app/config/rbac_roles.yaml")
        verdict = manager.check_permission(
            username="turkcell_junior",
            action="ssh_execute",
            command="systemctl restart nginx",
        )
        if verdict.status == PermissionStatus.DENIED:
            print(verdict.message)
    """

    def __init__(self, config_path: str | Path) -> None:
        self._config_path = Path(config_path)
        self._roles: dict[str, RoleConfig] = {}
        self._users: dict[str, UserConfig] = {}
        self._action_safety_map: dict[str, str] = {}
        self._fallback_role: str = "junior"
        self._max_commands_per_session: int = 100
        self._session_timeout_minutes: int = 60

        self._load_config()

    # --- Public Interface ---

    def check_permission(
        self,
        username: str,
        action: str,
        command: str = "",
    ) -> SecurityVerdict:
        """
        Check if a user is allowed to perform an action.

        This is the MAIN entry point called by the Router Agent.

        Args:
            username: The requesting user's identifier.
            action:   The action category (e.g., 'ssh_execute', 'network_diagnostics').
            command:  The actual shell command (for command-level blocking).

        Returns:
            SecurityVerdict with status, safety level, and explanation.
        """
        role_name = self.get_user_role(username)
        role = self._roles.get(role_name)

        if role is None:
            logger.error("Role '%s' not found in config for user '%s'", role_name, username)
            return SecurityVerdict(
                status=PermissionStatus.DENIED,
                user_role=role_name,
                action=action,
                safety_level=SafetyLevel.DANGEROUS,
                message=f"Turkcell Bilgi Güvenliği Politikaları (ISO 27001) gereği: Rol '{role_name}' tanımlı değil.",
                denied_reason="undefined_role",
            )

        # --- Check 1: Is the action in the role's allowed list? ---
        if action not in role.allowed_actions:
            logger.warning(
                "DENIED: User '%s' (role=%s) attempted action '%s' — not in allowed_actions",
                username, role_name, action,
            )
            return SecurityVerdict(
                status=PermissionStatus.DENIED,
                user_role=role_name,
                action=action,
                safety_level=self._get_safety_level(action),
                message=(
                    f"Turkcell Bilgi Güvenliği Politikaları (ISO 27001) gereği "
                    f"bu işleme yetkiniz bulunmamaktadır. "
                    f"Rol: '{role_name}' | İşlem: '{action}'"
                ),
                denied_reason="action_not_allowed",
            )

        # --- Check 2: Does the command contain blocked patterns? ---
        if command:
            blocked_match = self._check_command_blocklist(command, role)
            if blocked_match:
                logger.warning(
                    "BLOCKED: User '%s' (role=%s) command '%s' matched blocklist pattern '%s'",
                    username, role_name, command, blocked_match,
                )
                return SecurityVerdict(
                    status=PermissionStatus.DENIED,
                    user_role=role_name,
                    action=action,
                    safety_level=SafetyLevel.DANGEROUS,
                    message=(
                        f"Turkcell Bilgi Güvenliği Politikaları (ISO 27001) gereği "
                        f"bu komut engellenmiştir. "
                        f"Komut: '{command}' | Engellenen desen: '{blocked_match}'"
                    ),
                    denied_reason="command_blocked",
                    matched_blocked=blocked_match,
                )

        # --- Check 3: Does the safety level exceed the role's maximum? ---
        safety_level = self._resolve_safety_level(action, command)
        if not self._is_safety_level_permitted(safety_level, role):
            logger.warning(
                "DENIED: User '%s' (role=%s) — safety level '%s' exceeds max '%s'",
                username, role_name, safety_level.value, role.max_safety_level,
            )
            return SecurityVerdict(
                status=PermissionStatus.DENIED,
                user_role=role_name,
                action=action,
                safety_level=safety_level,
                message=(
                    f"Turkcell Bilgi Güvenliği Politikaları (ISO 27001) gereği "
                    f"bu işlem güvenlik seviyenizi aşmaktadır. "
                    f"Seviye: '{safety_level.value}' | Maksimum: '{role.max_safety_level}'"
                ),
                denied_reason="safety_level_exceeded",
            )

        # --- Check 4: Does this action require confirmation? ---
        if safety_level.value in role.requires_confirmation:
            logger.info(
                "CONFIRMATION REQUIRED: User '%s' (role=%s) — action '%s' (safety=%s)",
                username, role_name, action, safety_level.value,
            )
            return SecurityVerdict(
                status=PermissionStatus.REQUIRES_CONFIRMATION,
                user_role=role_name,
                action=action,
                safety_level=safety_level,
                message=(
                    f"⚠️ Confirmation Required: This action is classified as "
                    f"'{safety_level.value}'. Please confirm to proceed."
                ),
            )

        # --- All checks passed ---
        logger.info(
            "ALLOWED: User '%s' (role=%s) — action '%s' (safety=%s)",
            username, role_name, action, safety_level.value,
        )
        return SecurityVerdict(
            status=PermissionStatus.ALLOWED,
            user_role=role_name,
            action=action,
            safety_level=safety_level,
            message=f"✅ Action '{action}' permitted for role '{role_name}'.",
        )

    def get_user_role(self, username: str) -> str:
        """
        Resolve a username to its RBAC role.

        Falls back to the configured default role if the user
        is not found in the registry.
        """
        user = self._users.get(username)
        if user is not None:
            return user.role

        logger.info(
            "User '%s' not found in registry — using fallback role '%s'",
            username, self._fallback_role,
        )
        return self._fallback_role

    def get_role_info(self, role_name: str) -> RoleConfig | None:
        """Retrieve full role configuration by name."""
        return self._roles.get(role_name)

    def get_user_info(self, username: str) -> UserConfig | None:
        """Retrieve user configuration by username."""
        return self._users.get(username)

    def list_users(self) -> list[str]:
        """Return all registered usernames."""
        return list(self._users.keys())

    def list_roles(self) -> list[str]:
        """Return all defined role names."""
        return list(self._roles.keys())

    @property
    def max_commands_per_session(self) -> int:
        return self._max_commands_per_session

    @property
    def session_timeout_minutes(self) -> int:
        return self._session_timeout_minutes

    # --- Private: Config Loading ---

    def _load_config(self) -> None:
        """Parse the RBAC YAML config into structured objects."""
        if not self._config_path.exists():
            raise FileNotFoundError(
                f"RBAC config not found: {self._config_path}"
            )

        with open(self._config_path, "r", encoding="utf-8") as f:
            raw: dict[str, Any] = yaml.safe_load(f)

        if not raw:
            raise ValueError(f"RBAC config is empty: {self._config_path}")

        # Parse roles
        for role_name, role_data in raw.get("roles", {}).items():
            self._roles[role_name] = RoleConfig(
                name=role_name,
                description=role_data.get("description", ""),
                allowed_actions=role_data.get("allowed_actions", []),
                denied_commands=role_data.get("denied_commands", []),
                max_safety_level=role_data.get("max_safety_level", "safe"),
                requires_confirmation=role_data.get("requires_confirmation", []),
            )

        # Parse users
        for username, user_data in raw.get("users", {}).items():
            self._users[username] = UserConfig(
                username=username,
                role=user_data.get("role", self._fallback_role),
                full_name=user_data.get("full_name", ""),
                department=user_data.get("department", ""),
            )

        # Parse action → safety level map
        self._action_safety_map = raw.get("action_safety_map", {})

        # Parse defaults
        defaults = raw.get("defaults", {})
        self._fallback_role = defaults.get("fallback_role", "junior")
        self._max_commands_per_session = defaults.get("max_commands_per_session", 100)
        self._session_timeout_minutes = defaults.get("session_timeout_minutes", 60)

        logger.info(
            "RBAC config loaded: %d roles, %d users, %d action mappings",
            len(self._roles), len(self._users), len(self._action_safety_map),
        )

    # --- Private: Safety Level Resolution ---

    def _get_safety_level(self, action: str) -> SafetyLevel:
        """Look up the default safety level for an action category."""
        level_str = self._action_safety_map.get(action, "safe")
        try:
            return SafetyLevel(level_str)
        except ValueError:
            return SafetyLevel.SAFE

    def _resolve_safety_level(self, action: str, command: str) -> SafetyLevel:
        """
        Determine the safety level for an action + command pair.

        For 'dynamic' actions (like ssh_execute), the actual command
        is analyzed to determine the safety level.
        """
        base_level = self._get_safety_level(action)

        if base_level != SafetyLevel.DYNAMIC:
            return base_level

        # Dynamic classification based on command content
        return self._classify_command_safety(command)

    def _classify_command_safety(self, command: str) -> SafetyLevel:
        """
        Analyze a shell command and classify its safety level.

        This is used for 'dynamic' action types where the safety
        depends on WHAT command is being executed.
        """
        if not command:
            return SafetyLevel.SAFE

        normalized = command.strip().lower()

        # 🔴 DANGEROUS patterns
        dangerous_patterns: list[str] = [
            "rm -rf", "rm -r", "rmdir", "mkfs", "fdisk", "dd ",
            "shutdown", "reboot", "halt", "poweroff", "init 0", "init 6",
            "iptables -F", "iptables -X", "ufw disable",
            "chmod -R 777", "> /dev/", "format",
        ]
        for pattern in dangerous_patterns:
            if pattern in normalized:
                return SafetyLevel.DANGEROUS

        # 🟡 CAUTION patterns
        caution_patterns: list[str] = [
            "systemctl restart", "systemctl stop", "systemctl start",
            "systemctl enable", "systemctl disable",
            "service ", "apt install", "apt remove", "apt upgrade",
            "yum install", "yum remove", "yum update",
            "dnf install", "dnf remove", "dnf update",
            "useradd", "userdel", "usermod", "groupadd", "groupdel",
            "passwd", "chown", "chmod", "mount", "umount",
            "crontab -e", "crontab -r",
            "mv ", "cp ", "tee ", "sed -i", "awk ",
        ]
        for pattern in caution_patterns:
            if pattern in normalized:
                return SafetyLevel.CAUTION

        # 🟢 Everything else is considered safe
        return SafetyLevel.SAFE

    # --- Private: Command Blocklist Check ---

    def _check_command_blocklist(
        self, command: str, role: RoleConfig
    ) -> str:
        """
        Check if a command matches any blocked pattern for the role.

        Returns the matched pattern string, or empty string if no match.
        """
        normalized = command.strip().lower()

        for blocked in role.denied_commands:
            if blocked.lower() in normalized:
                return blocked

        return ""

    # --- Private: Safety Level Comparison ---

    @staticmethod
    def _is_safety_level_permitted(
        requested: SafetyLevel, role: RoleConfig
    ) -> bool:
        """
        Check if the requested safety level is within the role's maximum.

        Uses a numeric hierarchy: safe(0) < caution(1) < dangerous(2).
        """
        requested_rank = _SAFETY_LEVEL_HIERARCHY.get(requested.value, 0)
        max_rank = _SAFETY_LEVEL_HIERARCHY.get(role.max_safety_level, 0)
        return requested_rank <= max_rank
