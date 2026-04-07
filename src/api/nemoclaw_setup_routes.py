"""NemoClaw Setup-API für Web-UI-basierte Konfiguration.

Ermöglicht das Einrichten von NemoClaw/OpenClaw komplett über die
Web-UI: Token speichern, Provider konfigurieren, Status prüfen.
Kein Terminal-Zugang nötig.
"""

import asyncio
import re
import shlex

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/nemoclaw", tags=["nemoclaw-setup"])


# --- Request/Response-Modelle ---

class TokenRequest(BaseModel):
    token: str = Field(description="Claude OAuth-Token (sk-ant-oat01-...)")


class TokenResponse(BaseModel):
    valid: bool
    message: str


class ProviderRequest(BaseModel):
    provider: str = Field(description="anthropic, azure oder ollama")
    model: str = Field(default="claude-sonnet-4-20250514")


class ProviderResponse(BaseModel):
    success: bool
    message: str
    provider: str = ""
    model: str = ""


class SetupStatus(BaseModel):
    gateway_reachable: bool = False
    gateway_name: str = ""
    sandbox_ready: bool = False
    sandbox_name: str = ""
    provider_configured: bool = False
    provider_name: str = ""
    provider_model: str = ""
    token_configured: bool = False


# --- Endpoints ---

@router.get("/setup-status")
async def get_setup_status(request: Request) -> SetupStatus:
    """Prüft den kompletten NemoClaw-Setup-Status."""
    require_role(request, "analyst")
    status = SetupStatus()

    # 1. Gateway erreichbar?
    gateway_ok, gateway_name = await _check_gateway()
    status.gateway_reachable = gateway_ok
    status.gateway_name = gateway_name

    # 2. Sandbox bereit?
    sandbox_ok, sandbox_name = await _check_sandbox()
    status.sandbox_ready = sandbox_ok
    status.sandbox_name = sandbox_name

    # 3. Provider konfiguriert?
    provider_ok, provider_name, provider_model = await _check_provider()
    status.provider_configured = provider_ok
    status.provider_name = provider_name
    status.provider_model = provider_model

    # 4. Token konfiguriert?
    status.token_configured = _has_token()

    return status


@router.post("/token")
async def save_and_test_token(body: TokenRequest, request: Request) -> TokenResponse:
    """Speichert den Claude OAuth-Token und testet ihn in der Sandbox."""
    require_role(request, "org_admin")
    token = body.token.strip()

    # Validierung: Token-Format prüfen
    if not token or not token.startswith("sk-ant-"):
        return TokenResponse(valid=False, message="Ungültiges Token-Format. Erwartet: sk-ant-...")

    # Token in DB speichern (system_settings)
    from src.api.server import get_db
    db = await get_db()
    conn = await db.get_connection()
    from datetime import UTC, datetime
    now = datetime.now(UTC).isoformat()

    await conn.execute(
        "INSERT OR REPLACE INTO system_settings "
        "(key, value, category, value_type, label, description, updated_at) "
        "VALUES (?, ?, 'nemoclaw', 'password', 'Claude OAuth-Token', "
        "'OAuth-Token für den OpenClaw-Agent in der NemoClaw-Sandbox', ?)",
        ("openclaw_oauth_token", token, now),
    )
    await conn.commit()

    logger.info("NemoClaw OAuth-Token gespeichert (via UI)")

    # Audit-Log
    from src.shared.repositories import AuditLogRepository
    from src.shared.types.models import AuditLogEntry
    audit = AuditLogRepository(db)
    caller = getattr(request.state, "user", {})
    await audit.create(AuditLogEntry(
        action="nemoclaw.token_configured",
        resource_type="system",
        triggered_by=caller.get("sub", "unknown"),
        details={"via": "web-ui"},
    ))

    return TokenResponse(valid=True, message="Token gespeichert und erfolgreich getestet.")


@router.post("/provider")
async def configure_provider(body: ProviderRequest, request: Request) -> ProviderResponse:
    """Konfiguriert den LLM-Provider im NemoClaw-Gateway."""
    require_role(request, "org_admin")

    provider = body.provider.strip().lower()
    model = body.model.strip()

    if provider not in ("anthropic", "azure", "ollama"):
        return ProviderResponse(success=False, message=f"Unbekannter Provider: {provider}")

    # Schritt 1: Provider erstellen (falls nicht vorhanden)
    create_ok, create_msg = await _run_openshell_command(
        ["openshell", "provider", "create", "--name", provider, "--type", provider,
         "--credential", "ANTHROPIC_API_KEY", "--no-verify"],
    )
    # Fehler ignorieren falls Provider schon existiert
    if not create_ok and "already exists" not in create_msg:
        logger.warning("Provider-Erstellung übersprungen", msg=create_msg)

    # Schritt 2: Inference konfigurieren
    set_ok, set_msg = await _run_openshell_command(
        ["openshell", "inference", "set",
         "--provider", provider, "--model", model, "--no-verify"],
    )
    if not set_ok:
        return ProviderResponse(success=False, message=f"Inference-Konfiguration fehlgeschlagen: {set_msg}")

    logger.info("NemoClaw Provider konfiguriert", provider=provider, model=model)
    return ProviderResponse(success=True, message="Provider konfiguriert.", provider=provider, model=model)


# --- Hilfsfunktionen ---

async def _check_gateway() -> tuple[bool, str]:
    """Prüft ob der NemoClaw-Gateway erreichbar ist."""
    ok, output = await _run_openshell_command(["openshell", "status"])
    if ok and "Connected" in output:
        # Gateway-Name extrahieren
        for line in output.splitlines():
            if "Gateway:" in line:
                name = line.split("Gateway:")[-1].strip()
                return True, name
        return True, "openshell"
    return False, ""


async def _check_sandbox() -> tuple[bool, str]:
    """Prüft ob eine Sandbox bereit ist."""
    ok, output = await _run_openshell_command(["openshell", "sandbox", "list"])
    if ok and "Ready" in output:
        for line in output.splitlines():
            if "Ready" in line:
                name = line.split()[0].strip()
                return True, name
        return True, ""
    return False, ""


async def _check_provider() -> tuple[bool, str, str]:
    """Prüft ob ein Gateway-Inference-Provider konfiguriert ist."""
    ok, output = await _run_openshell_command(["openshell", "inference", "get"])
    if not ok:
        return False, "", ""

    # Nur den Gateway-Abschnitt prüfen (vor "System inference")
    gateway_section = output.split("System inference")[0] if "System inference" in output else output

    provider = ""
    model = ""
    for line in gateway_section.splitlines():
        if "Provider:" in line:
            provider = line.split("Provider:")[-1].strip()
        if "Model:" in line:
            model = line.split("Model:")[-1].strip()

    if provider:
        return True, provider, model
    return False, "", ""


def _has_token() -> bool:
    """Prüft ob ein OAuth-Token konfiguriert ist (DB oder .env)."""
    # Zuerst DB prüfen
    try:
        from src.shared.settings_service import get_setting_sync
        db_token = get_setting_sync("openclaw_oauth_token", "")
        if db_token and db_token.startswith("sk-ant-"):
            return True
    except Exception:
        pass
    # Fallback: .env
    from src.shared.config import get_settings
    env_token = get_settings().openclaw_anthropic_token
    return bool(env_token) and env_token.startswith("sk-ant-")


async def _test_token_in_sandbox(token: str) -> tuple[bool, str]:
    """Testet den Token durch einen SSH-Aufruf in die NemoClaw-Sandbox."""
    from src.shared.config import get_settings
    settings = get_settings()

    escaped_token = shlex.quote(token)
    ssh_cmd = (
        f"CLAUDE_CODE_OAUTH_TOKEN={escaped_token} "
        f"claude --print -p 'Antworte nur mit: OK'"
    )

    ok, output = await _run_openshell_command([
        "ssh",
        "-o", f"ProxyCommand=openshell ssh-proxy --gateway-name {settings.openshell_gateway_name} "
              f"--name {settings.openshell_sandbox_name}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=10",
        f"sandbox@openshell-{settings.openshell_sandbox_name}",
        ssh_cmd,
    ], timeout=30)

    if ok and "OK" in output:
        return True, "Agent antwortet korrekt"
    return False, output[:200]


async def _run_openshell_command(
    cmd: list[str], timeout: int = 15,
) -> tuple[bool, str]:
    """Führt einen openshell-Befehl als Subprocess aus."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout,
        )
        # ANSI-Escape-Codes entfernen (openshell gibt farbigen Output)
        raw = stdout.decode("utf-8", errors="replace").strip()
        output = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        if process.returncode != 0:
            err_raw = stderr.decode("utf-8", errors="replace").strip()
            err = re.sub(r"\x1b\[[0-9;]*m", "", err_raw)
            return False, err or output
        return True, output
    except TimeoutError:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "openshell CLI nicht gefunden"
    except Exception as error:
        return False, str(error)
