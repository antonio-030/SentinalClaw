"""
OpenShell Sandbox-Policy-Manager für SentinelClaw.

Generiert und aktualisiert die Netzwerk-Policy der OpenShell-Sandbox
basierend auf den autorisierten Scan-Zielen. Die bestehende Policy
(Claude API, PyPI, GitHub, etc.) bleibt erhalten — nur der
scan_targets Block wird hinzugefügt oder aktualisiert.
"""

import asyncio
import tempfile
from pathlib import Path

from src.shared.config import get_settings
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)


async def _run_openshell_command(args: list[str], timeout: int = 30) -> str:
    """Führt einen openshell CLI-Befehl aus."""
    proc = await asyncio.create_subprocess_exec(
        "openshell", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    output = stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        err = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"openshell Fehler: {err[:300]}")
    return output


async def get_current_policy() -> str:
    """Liest die aktuelle Policy als YAML."""
    settings = get_settings()
    output = await _run_openshell_command([
        "policy", "get", settings.openshell_sandbox_name,
        "-g", settings.openshell_gateway_name, "--full",
    ])
    # Header-Zeilen (Version, Hash, etc.) überspringen — ab "---"
    if "---" in output:
        return output.split("---", 1)[1].strip()
    return output


def _build_scan_targets_block(targets: list[str]) -> str:
    """Baut den scan_targets YAML-Block für autorisierte Ziele."""
    if not targets:
        return ""

    endpoints: list[str] = []
    for target in targets:
        target = target.strip()
        endpoints.append(f"    - host: {target}\n      port: 80")
        endpoints.append(f"    - host: {target}\n      port: 443")

    endpoints_yaml = "\n".join(endpoints)
    return f"""  scan_targets:
    name: pentest-targets
    endpoints:
{endpoints_yaml}
    binaries:
    - path: /usr/bin/curl
    - path: /sandbox/.venv/bin/python
    - path: /sandbox/.venv/bin/python3"""


def _build_mcp_server_block() -> str:
    """Baut den YAML-Block für MCP-Server-Zugriff aus der Sandbox."""
    from src.shared.config import get_settings
    settings = get_settings()
    mcp_host = settings.mcp_gateway_host or "10.200.0.1"
    mcp_port = settings.mcp_gateway_port or 8081
    return f"""  mcp_server:
    name: sentinelclaw-mcp
    endpoints:
    - host: {mcp_host}
      port: {mcp_port}
    binaries:
    - path: /usr/bin/curl
    - path: /sandbox/.venv/bin/python
    - path: /sandbox/.venv/bin/python3"""


async def update_policy_with_targets(targets: list[str]) -> dict:
    """Aktualisiert die OpenShell-Policy mit den autorisierten Scan-Zielen."""
    settings = get_settings()

    # Aktuelle Policy lesen
    current = await get_current_policy()

    # Alte SentinelClaw-Blöcke entfernen (scan_targets + mcp_server)
    lines = current.splitlines()
    new_lines: list[str] = []
    skip = False
    for line in lines:
        # Block-Start erkennen (unsere eingefügten Blöcke)
        stripped = line.strip()
        if stripped.startswith("scan_targets:") or stripped.startswith("mcp_server:"):
            skip = True
            continue
        # Block-Ende: nächster Top-Level-Key unter network_policies (2 Spaces Einrückung)
        if skip and line and not line.startswith("    ") and not line.startswith("  -"):
            skip = False
        if skip:
            continue
        new_lines.append(line)

    cleaned = "\n".join(new_lines).rstrip()

    # MCP-Server + scan_targets Block einfügen
    mcp_block = _build_mcp_server_block()
    scan_block = _build_scan_targets_block(targets)
    extra_blocks = "\n".join(b for b in [mcp_block, scan_block] if b)
    updated = cleaned + "\n" + extra_blocks + "\n" if extra_blocks else cleaned + "\n"

    # Policy-Datei schreiben und anwenden
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False,
    ) as tmp:
        tmp.write(updated)
        tmp_path = tmp.name

    try:
        result = await _run_openshell_command([
            "policy", "set", settings.openshell_sandbox_name,
            "-g", settings.openshell_gateway_name,
            "--policy", tmp_path,
            "--wait", "--timeout", "30",
        ], timeout=40)
        logger.info("OpenShell-Policy aktualisiert", targets=len(targets))
        return {"status": "applied", "targets": len(targets), "output": result[:200]}
    except Exception as error:
        logger.error("Policy-Update fehlgeschlagen", error=str(error))
        return {"status": "failed", "error": str(error)}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


async def get_policy_status() -> dict:
    """Gibt den aktuellen Policy-Status zurück."""
    settings = get_settings()
    try:
        output = await _run_openshell_command([
            "policy", "get", settings.openshell_sandbox_name,
            "-g", settings.openshell_gateway_name,
        ])
        # Header parsen
        info: dict = {}
        for line in output.splitlines():
            if "Version:" in line:
                info["version"] = line.split(":", 1)[1].strip()
            elif "Hash:" in line:
                info["hash"] = line.split(":", 1)[1].strip()
            elif "Status:" in line:
                info["status"] = line.split(":", 1)[1].strip()
        return info
    except Exception as error:
        return {"status": "unreachable", "error": str(error)}
