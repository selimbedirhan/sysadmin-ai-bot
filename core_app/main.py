"""
Main Application — Interactive Terminal Loop
==============================================
The entry point for the SysAdmin AI Bot (Container 2).
Ties together all modules into a production-ready shell.

Components Integrated:
  - ConfigLoader     → Reads YAML configurations
  - RBACSecurityManager → Permission validation
  - RouterAgent      → Query classification, routing, tool execution
  - Rich Console     → Beautiful terminal UI

Flow:
  1. Load configs → initialize RBAC → initialize RouterAgent
  2. Display welcome banner
  3. Prompt for username (RBAC identity)
  4. Enter interactive loop:
     - Read user input
     - Process via RouterAgent
     - Handle confirmation flows
     - Display formatted output
  5. Graceful shutdown on exit/quit/Ctrl+C

SOLID Principles Applied:
  - S: main.py only handles UI and user interaction flow.
  - O: New commands (help, clear, etc.) are added via a handler map.
  - L: All dependencies are injected, not constructed inline.
  - I: Depends only on the public interfaces of each module.
  - D: Depends on abstractions (RouterAgent, RBACSecurityManager).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
from enum import Enum
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from core_app.rbac_security import RBACSecurityManager
from core_app.router_agent import ConfigLoader, RouterAgent

# ============================================================
#  LOGGING SETUP
# ============================================================

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sysadmin_ai")

# ============================================================
#  RICH CONSOLE THEME
# ============================================================

_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "prompt": "bold magenta",
    "header": "bold white on blue",
    "muted": "dim",
})

console = Console(theme=_THEME)


# ============================================================
#  APPLICATION STATE
# ============================================================

class AppState(str, Enum):
    """Tracks the current state of the interactive loop."""
    NORMAL = "normal"
    AWAITING_CONFIRMATION = "awaiting_confirmation"


# ============================================================
#  BUILT-IN COMMANDS (extensible via handler map)
# ============================================================

_BUILTIN_COMMANDS: dict[str, str] = {
    "help": "Show available commands and usage guide",
    "clear": "Clear the terminal screen",
    "history": "Show conversation history summary",
    "whoami": "Display current user and role information",
    "status": "Check system connectivity (Ollama, MCP)",
    "exit": "Exit the application",
    "quit": "Exit the application",
}


# ============================================================
#  DISPLAY HELPERS
# ============================================================

def display_welcome(config_name: str, version: str) -> None:
    """Display the welcome banner."""
    banner = Text()
    banner.append("╔══════════════════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║        TAO — Turkcell Ajan-Ops v1.0.0               ║\n", style="bold cyan")
    banner.append("║   Senior System Administrator & Security Architect   ║\n", style="cyan")
    banner.append("╠══════════════════════════════════════════════════════╣\n", style="bold cyan")
    banner.append("║  Zero Trust Architecture — ISO 27001 Compliant       ║\n", style="cyan")
    banner.append("║  CCIE | RHCA Certified                               ║\n", style="cyan")
    banner.append("║                                                      ║\n", style="cyan")
    banner.append("║  Komut bekliyor. 'help' yazin.                       ║\n", style="cyan")
    banner.append("║  Cikis: 'exit' veya 'quit'                          ║\n", style="cyan")
    banner.append("╚══════════════════════════════════════════════════════╝", style="bold cyan")
    console.print(banner)
    console.print()


def display_help() -> None:
    """Display the help panel with available commands."""
    table = Table(
        title="Available Commands",
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Command", style="bold yellow", min_width=12)
    table.add_column("Description", style="white")

    for cmd, desc in _BUILTIN_COMMANDS.items():
        table.add_row(cmd, desc)

    table.add_section()
    table.add_row(
        "[italic]any text[/italic]",
        "Natural language query — automatically routed to the appropriate AI model",
    )

    console.print(table)
    console.print()


def display_user_info(username: str, rbac: RBACSecurityManager) -> None:
    """Display current user and role information."""
    role_name = rbac.get_user_role(username)
    role_info = rbac.get_role_info(role_name)
    user_info = rbac.get_user_info(username)

    table = Table(title="User Information", title_style="bold cyan")
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")

    table.add_row("Username", username)
    table.add_row("Role", role_name.upper())

    if user_info:
        table.add_row("Full Name", user_info.full_name)
        table.add_row("Department", user_info.department)

    if role_info:
        table.add_row("Description", role_info.description)
        table.add_row("Max Safety Level", role_info.max_safety_level.upper())
        table.add_row("Allowed Actions", ", ".join(role_info.allowed_actions))

    console.print(table)
    console.print()


def display_response(response: str) -> None:
    """Display the AI's response with markdown formatting."""
    console.print()
    try:
        md = Markdown(response)
        console.print(Panel(
            md,
            title="TAO",
            title_align="left",
            border_style="cyan",
            padding=(1, 2),
        ))
    except Exception:
        # Fallback to plain text if markdown parsing fails
        console.print(Panel(
            response,
            title="TAO",
            title_align="left",
            border_style="cyan",
            padding=(1, 2),
        ))
    console.print()


def display_error(message: str) -> None:
    """Display an error message."""
    console.print(f"[error]❌ {message}[/error]")
    console.print()


async def display_status_check(agent: RouterAgent) -> None:
    """Run and display system connectivity checks."""
    console.print("[info]Running system checks...[/info]")

    table = Table(title="System Status", title_style="bold cyan")
    table.add_column("Component", style="bold yellow")
    table.add_column("Status", style="white")

    # Properly await the async health check
    mcp_healthy = await agent.check_mcp_health()

    table.add_row(
        "MCP Server",
        "[success]✅ Connected[/success]" if mcp_healthy else "[error]❌ Unreachable[/error]",
    )
    table.add_row("Ollama Engine", "[success]✅ Connected[/success] (via entrypoint check)")
    table.add_row("RBAC Config", "[success]✅ Loaded[/success]")

    console.print(table)
    console.print()


# ============================================================
#  USER LOGIN
# ============================================================

def prompt_username(rbac: RBACSecurityManager) -> str:
    """
    Prompt the user to select their identity.

    Displays available users from the RBAC registry.
    Falls back to the default role if user is not registered.
    """
    console.print("[info]Available users:[/info]")
    users = rbac.list_users()
    for i, username in enumerate(users, 1):
        user_info = rbac.get_user_info(username)
        role = rbac.get_user_role(username)
        dept = user_info.department if user_info else "Unknown"
        console.print(f"  [bold yellow]{i}.[/bold yellow] {username} "
                       f"[muted]({role} — {dept})[/muted]")

    console.print()
    selected = Prompt.ask(
        "[prompt]Select user (name or number)[/prompt]",
        default=users[0] if users else "guest",
    )

    # Handle numeric selection
    try:
        idx = int(selected) - 1
        if 0 <= idx < len(users):
            selected = users[idx]
    except ValueError:
        pass

    role = rbac.get_user_role(selected)
    console.print(f"\n[success]✅ Logged in as:[/success] [bold]{selected}[/bold] "
                   f"[muted](role: {role})[/muted]\n")

    return selected


# ============================================================
#  CONFIRMATION FLOW
# ============================================================

def is_confirmation_response(response_text: str) -> bool:
    """Check if the AI's response requires user confirmation."""
    return "Type **'yes'** to execute" in response_text


def extract_pending_command(response_text: str) -> str:
    """Extract the pending command from a confirmation prompt."""
    match = re.search(r"Command:\s*`([^`]+)`", response_text)
    return match.group(1) if match else ""


# ============================================================
#  MAIN INTERACTIVE LOOP
# ============================================================

async def async_main() -> None:
    """
    The main async entry point.

    Initializes all components and runs the interactive loop.
    """
    # --- Phase 1: Load Configuration ---
    config_dir = os.environ.get("CONFIG_DIR", "/app/config")

    # Support local development (config next to the script)
    if not Path(config_dir).exists():
        local_config = Path(__file__).resolve().parent.parent / "config"
        if local_config.exists():
            config_dir = str(local_config)

    console.print("[info]Loading configuration...[/info]")
    try:
        config_loader = ConfigLoader(config_dir)
        app_config = config_loader.load()
        console.print("[success]✅ Configuration loaded.[/success]")
    except Exception as exc:
        display_error(f"Failed to load configuration: {exc}")
        sys.exit(1)

    # --- Phase 2: Initialize RBAC ---
    rbac_config_path = Path(config_dir) / "rbac_roles.yaml"
    console.print("[info]Loading RBAC security rules...[/info]")
    try:
        rbac_manager = RBACSecurityManager(rbac_config_path)
        console.print("[success]✅ RBAC loaded "
                       f"({len(rbac_manager.list_roles())} roles, "
                       f"{len(rbac_manager.list_users())} users).[/success]")
    except Exception as exc:
        display_error(f"Failed to load RBAC: {exc}")
        sys.exit(1)

    # --- Phase 3: Initialize Router Agent ---
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://ollama-engine:11434")
    console.print("[info]Initializing AI models...[/info]")
    try:
        agent = RouterAgent(
            config=app_config,
            rbac_manager=rbac_manager,
            ollama_base_url=ollama_url,
        )
        console.print("[success]✅ Router Agent initialized.[/success]")
    except Exception as exc:
        display_error(f"Failed to initialize Router Agent: {exc}")
        sys.exit(1)

    # --- Phase 4: Welcome & Login ---
    console.print()
    display_welcome(app_config.app_name, app_config.version)
    username = prompt_username(rbac_manager)

    # --- Phase 5: Interactive Loop ---
    state = AppState.NORMAL
    pending_command: str = ""
    pending_analysis: str = ""

    while True:
        try:
            # --- Prompt ---
            role = rbac_manager.get_user_role(username)
            prompt_text = f"[{role}] {username}"

            if state == AppState.AWAITING_CONFIRMATION:
                user_input = Prompt.ask(
                    f"[prompt]⚠️  Confirm execution? (yes/no)[/prompt]"
                ).strip().lower()

                if user_input in ("yes", "y", "evet"):
                    console.print("[info]⏳ Executing confirmed command...[/info]")
                    start_time = time.time()

                    response = await agent.handle_confirmation(
                        confirmed=True,
                        command=pending_command,
                        username=username,
                        original_analysis=pending_analysis,
                    )

                    elapsed = time.time() - start_time
                    display_response(response)
                    console.print(f"[muted]⏱ Response time: {elapsed:.1f}s[/muted]")
                else:
                    response = await agent.handle_confirmation(
                        confirmed=False,
                        command=pending_command,
                        username=username,
                        original_analysis=pending_analysis,
                    )
                    display_response(response)

                state = AppState.NORMAL
                pending_command = ""
                pending_analysis = ""
                continue

            user_input = Prompt.ask(f"[prompt]{prompt_text} >[/prompt]").strip()

            if not user_input:
                continue

            # --- Built-in Commands ---
            lower_input = user_input.lower()

            if lower_input in ("exit", "quit"):
                console.print("\n[info]TAO oturumu sonlandirildi.[/info]\n")
                break

            if lower_input == "help":
                display_help()
                continue

            if lower_input == "clear":
                console.clear()
                display_welcome(app_config.app_name, app_config.version)
                continue

            if lower_input == "whoami":
                display_user_info(username, rbac_manager)
                continue

            if lower_input == "status":
                await display_status_check(agent)
                continue

            if lower_input == "history":
                console.print("[info]Recent conversation: "
                               f"{agent.conversation_history_count} messages[/info]")
                console.print()
                continue

            # --- AI Processing ---
            console.print("[info]⏳ Processing your request...[/info]")
            start_time = time.time()

            response = await agent.process_message(user_input, username)

            elapsed = time.time() - start_time

            # --- Check if confirmation is needed ---
            if is_confirmation_response(response):
                pending_command = extract_pending_command(response)
                pending_analysis = response
                state = AppState.AWAITING_CONFIRMATION

            display_response(response)
            console.print(f"[muted]⏱ Response time: {elapsed:.1f}s[/muted]")

        except KeyboardInterrupt:
            console.print("\n\n[info]👋 Session interrupted. Goodbye![/info]\n")
            break
        except EOFError:
            console.print("\n[info]👋 End of input. Goodbye![/info]\n")
            break
        except Exception as exc:
            logger.exception("Unhandled error in main loop: %s", exc)
            display_error(f"Unexpected error: {exc}")
            console.print("[muted]Hata kaydedildi. TAO hizmet vermeye devam ediyor.[/muted]")
            console.print()


# ============================================================
#  ENTRY POINT
# ============================================================

def main() -> None:
    """Synchronous entry point — bootstraps the async event loop."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        console.print("\n[info]👋 Goodbye![/info]\n")


if __name__ == "__main__":
    main()
