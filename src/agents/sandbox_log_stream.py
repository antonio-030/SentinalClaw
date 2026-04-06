"""
Live-Log-Streaming aus der NemoClaw-Sandbox.

Streamt Sandbox-Logs parallel zum Agent-Aufruf über WebSocket
ans Frontend. Nutzt 'nemoclaw logs --follow' oder 'docker logs'
als Fallback im Entwicklungsmodus.
"""

import asyncio
import re
import shutil

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Alle Terminal-Steuerzeichen entfernen (ANSI, CSI, OSC, TTY)
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[a-zA-Z]"   # CSI-Sequenzen (Farben, Cursor)
    r"|\x1b\][^\x07]*\x07"       # OSC-Sequenzen
    r"|\x1b[()][A-Z0-9]"         # Charset-Switching
    r"|\x1b[>=<]"                 # Keypad/Mode
    r"|\x1b\[[\?]?[0-9;]*[hl]"   # DEC Private Mode
    r"|\r"                         # Carriage Return
    r"|[\x00-\x08\x0e-\x1f]"     # Nicht-druckbare Steuerzeichen
)


async def stream_sandbox_logs(sandbox_name: str) -> None:
    """Streamt NemoClaw/Docker Sandbox-Logs parallel über WebSocket."""
    try:
        from src.api.websocket_manager import ws_manager
    except Exception:
        return

    # NemoClaw-Logs wenn verfügbar, sonst Docker-Logs als Fallback
    if shutil.which("nemoclaw"):
        cmd = ["nemoclaw", sandbox_name, "logs", "--follow"]
    else:
        cmd = [
            "docker", "logs", "sentinelclaw-sandbox",
            "-f", "--since", "1s",
        ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception:
        return

    try:
        assert proc.stdout is not None
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").rstrip()
            line = _ANSI_RE.sub("", line).strip()
            if not line:
                continue
            event = classify_log_line(line)
            try:
                await ws_manager.broadcast("agent_step", event)
            except Exception:
                pass
    except asyncio.CancelledError:
        proc.kill()
    except Exception:
        pass


def classify_log_line(line: str) -> dict:
    """Klassifiziert eine Log-Zeile in ein WebSocket-Event."""
    lower = line.lower()

    # Tool-Aufrufe
    if any(k in lower for k in ("exec:", "bash:", "tool:", "$ ", "❯ ")):
        return {"type": "tool_start", "tool": "bash", "command": line[:200]}

    # Inference / Denken
    if any(k in lower for k in ("inference:", "llm:", "thinking", "generating")):
        return {"type": "thinking", "message": line[:200]}

    # Netzwerk
    if any(k in lower for k in ("egress:", "network:", "connect:")):
        return {
            "type": "tool_start", "tool": "network", "command": line[:200],
        }

    # Erfolg
    if any(k in lower for k in ("result:", "output:", "✓", "✅", "success")):
        return {
            "type": "tool_result", "success": True,
            "output_preview": line[:200],
        }

    # Fehler
    if any(k in lower for k in ("error:", "failed:", "✗", "❌", "denied")):
        return {
            "type": "tool_result", "success": False,
            "output_preview": line[:200],
        }

    # Allgemeine Log-Zeile
    return {"type": "log", "message": line[:300]}
