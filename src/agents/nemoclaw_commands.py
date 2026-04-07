"""
Hilfsfunktionen für NemoClaw-Befehlsbau.

Ausgelagert aus nemoclaw_runtime.py um die 300-Zeilen-Regel
einzuhalten. Baut SSH-Befehle, CLI-Commands und User-Messages
für die OpenClaw-Agent-Runtime.
"""

import shlex

from src.shared.types.agent_runtime import OpenClawConfig


def build_ssh_command(config: OpenClawConfig) -> list[str]:
    """Baut den SSH-Befehl für die Verbindung zur OpenShell-Sandbox."""
    proxy_cmd = (
        f"openshell ssh-proxy "
        f"--gateway-name {config.gateway_name} "
        f"--name {config.sandbox_name}"
    )
    return [
        "ssh",
        "-o", f"ProxyCommand={proxy_cmd}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", f"ConnectTimeout={config.ssh_timeout}",
        f"sandbox@openshell-{config.sandbox_name}",
    ]


def build_allowed_tools_pattern() -> str:
    """Baut das Bash-Allowlist-Pattern für OpenClaw.

    Liest die erlaubten Binaries aus den Settings (konfigurierbar über Web-UI).
    Paketmanager werden IMMER aus der Liste entfernt, auch wenn jemand
    sie in den Settings einträgt — Defense in Depth.
    """
    from src.shared.settings_service import get_setting_sync

    # Erlaubte Binaries aus Settings laden (komma-getrennt)
    configured = get_setting_sync(
        "agent_allowed_binaries",
        "curl,dig,whois,nmap,nuclei,python3,wget,jq",
    )
    allowed = {b.strip() for b in configured.split(",") if b.strip()}

    # Blockierte Binaries aus Settings laden und ENTFERNEN
    blocked_str = get_setting_sync(
        "agent_blocked_binaries",
        "pip,pip3,apt,apt-get,npm,yarn,brew,cargo,gem",
    )
    blocked = {b.strip() for b in blocked_str.split(",") if b.strip()}
    allowed -= blocked

    # Analyse-Utilities die der Agent immer braucht
    allowed |= {"cat", "head", "tail", "grep", "ls", "wc", "sort"}

    pattern = "|".join(sorted(allowed))
    return pattern


def build_cli_command(
    system_prompt: str,
    user_message: str,
    session_id: str = "",
) -> str:
    """Baut den Claude Code Agent-Befehl für die Sandbox.

    Nutzt Claude Code CLI mit dem Abo-OAuth-Token direkt.
    Die Sandbox (OpenShell) liefert Isolation (Landlock + seccomp).
    Bash ist auf eine Allowlist beschränkt (konfigurierbar über Web-UI).
    """
    escaped_message = shlex.quote(user_message)
    allowed_pattern = build_allowed_tools_pattern()

    # OAuth-Token für Claude Code Abo
    token = _get_oauth_token()
    token_export = f"export CLAUDE_CODE_OAUTH_TOKEN={shlex.quote(token)} && " if token else ""

    return (
        f"{token_export}"
        f"cd /sandbox && "
        f"claude --print "
        f"--allowedTools 'Bash({allowed_pattern})' "
        f"-p {escaped_message}"
    )


def _get_oauth_token() -> str:
    """Liest den OAuth-Token: zuerst aus DB (über UI gesetzt), Fallback auf .env."""
    try:
        from src.shared.settings_service import get_setting_sync
        db_token = get_setting_sync("openclaw_oauth_token", "")
        if db_token and db_token.startswith("sk-ant-"):
            return db_token
    except Exception:
        pass
    from src.shared.config import get_settings
    return get_settings().openclaw_anthropic_token


def build_user_message(
    current_message: str, messages: list[dict[str, str]] | None,
) -> str:
    """Baut User-Nachricht mit optionaler Chat-History als Kontext-Block."""
    if not messages:
        return current_message
    parts = []
    for msg in messages[:-1]:
        role = "User" if msg["role"] == "user" else "Agent"
        parts.append(f"[{role}]: {msg['content']}")
    if not parts:
        return current_message
    return f"[Chat-Verlauf]\n{chr(10).join(parts)}\n\n[Nachricht]\n{current_message}"


async def push_ws_line_event(ws_manager: object, line: str, line_count: int) -> None:
    """Klassifiziert eine stdout-Zeile und pusht sie über WebSocket."""
    # Tool-Erkennung: Bash-Befehle und deren Output
    if line.startswith("$ ") or line.startswith("❯ "):
        await ws_manager.broadcast("agent_step", {  # type: ignore[attr-defined]
            "type": "tool_start",
            "tool": "bash",
            "command": line[2:][:200],
        })
    elif line.startswith("✓") or line.startswith("✅"):
        await ws_manager.broadcast("agent_step", {  # type: ignore[attr-defined]
            "type": "tool_result",
            "tool": "bash",
            "success": True,
            "output_preview": line[:200],
        })
    elif line.startswith("✗") or line.startswith("❌"):
        await ws_manager.broadcast("agent_step", {  # type: ignore[attr-defined]
            "type": "tool_result",
            "tool": "bash",
            "success": False,
            "output_preview": line[:200],
        })
    elif line_count % 10 == 0:
        # Alle 10 Zeilen ein Thinking-Update
        await ws_manager.broadcast("agent_step", {  # type: ignore[attr-defined]
            "type": "thinking",
            "message": f"Agent arbeitet... ({line_count} Zeilen)",
        })
