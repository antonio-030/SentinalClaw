"""
Chat-Routen fuer die SentinelClaw REST-API.

Agent-Chat-System — Benutzer kommunizieren mit dem KI-Agenten.
Nachrichten werden in der DB persistiert. Scan-Befehle werden
erkannt und im Hintergrund gestartet.

Endpoints:
  - POST  /api/v1/chat          -> Nachricht senden, Antwort erhalten
  - GET   /api/v1/chat/history   -> Chat-Verlauf abrufen (optional scan_id)
"""

import asyncio
import re
import shutil
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/chat", tags=["Chat"])


# ─── Request/Response Modelle ──────────────────────────────────────


class ChatRequest(BaseModel):
    """Eingehende Chat-Nachricht vom Benutzer."""

    message: str = Field(description="Nachricht des Benutzers")
    scan_id: str | None = Field(default=None, description="Optionale Scan-ID fuer Kontext")


class ChatResponseModel(BaseModel):
    """Antwort des Agenten."""

    response: str
    scan_started: bool = False
    scan_id: str | None = None


class ChatMessageOut(BaseModel):
    """Einzelne Chat-Nachricht fuer den Verlauf."""

    id: str
    scan_id: str | None
    role: str
    content: str
    message_type: str
    created_at: str


# ─── Hilfsfunktion: DB-Zugriff ────────────────────────────────────


async def _get_db():
    """Importiert get_db aus server.py um zirkulaere Imports zu vermeiden."""
    from src.api.server import get_db
    return await get_db()


# ─── Chat-Nachrichten in DB speichern/laden ───────────────────────


async def _save_message(
    role: str,
    content: str,
    scan_id: str | None = None,
    message_type: str = "text",
) -> str:
    """Speichert eine Chat-Nachricht in der Datenbank. Gibt die ID zurueck."""
    db = await _get_db()
    conn = await db.get_connection()
    msg_id = str(uuid4())
    now = datetime.now(UTC).isoformat()

    await conn.execute(
        """INSERT INTO chat_messages (id, scan_id, role, content, message_type, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (msg_id, scan_id, role, content, message_type, now),
    )
    await conn.commit()
    return msg_id


async def _load_history(scan_id: str | None = None, limit: int = 100) -> list[dict]:
    """Laedt Chat-Verlauf, optional gefiltert nach scan_id."""
    db = await _get_db()
    conn = await db.get_connection()

    if scan_id:
        cursor = await conn.execute(
            """SELECT id, scan_id, role, content, message_type, created_at
               FROM chat_messages
               WHERE scan_id = ?
               ORDER BY created_at ASC
               LIMIT ?""",
            (scan_id, limit),
        )
    else:
        cursor = await conn.execute(
            """SELECT id, scan_id, role, content, message_type, created_at
               FROM chat_messages
               ORDER BY created_at ASC
               LIMIT ?""",
            (limit,),
        )

    rows = await cursor.fetchall()
    return [
        {
            "id": row[0],
            "scan_id": row[1],
            "role": row[2],
            "content": row[3],
            "message_type": row[4],
            "created_at": row[5],
        }
        for row in rows
    ]


# ─── Scan-Befehl-Erkennung ───────────────────────────────────────

# Muster fuer IP-Adressen, CIDRs und Domains
_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
# Deutsche und englische Scan-Schluesselwoerter
_SCAN_KEYWORDS = re.compile(
    r"\b(scan|scanne|prüfe|pruefe|teste|nmap|nuclei|port\s*scan|vuln\s*scan|recon)\b",
    re.IGNORECASE,
)


def _detect_scan_command(message: str) -> tuple[bool, str | None]:
    """
    Erkennt ob eine Nachricht ein Scan-Befehl ist.
    Gibt (is_scan, target) zurueck.
    """
    has_keyword = bool(_SCAN_KEYWORDS.search(message))
    if not has_keyword:
        return False, None

    # Versuche IP/CIDR zu extrahieren
    ip_match = _IP_PATTERN.search(message)
    if ip_match:
        return True, ip_match.group()

    # Versuche Domain zu extrahieren
    domain_match = _DOMAIN_PATTERN.search(message)
    if domain_match:
        return True, domain_match.group()

    return False, None


def _is_findings_question(message: str) -> bool:
    """Erkennt ob eine Nachricht eine Frage zu Scan-Ergebnissen ist."""
    keywords = re.compile(
        r"\b(finding|ergebnis|resultat|schwachstelle|vulnerability|vuln|"
        r"was wurde gefunden|was gefunden|zeige|show|report|bericht|zusammenfassung|summary|"
        r"critical|high|medium|low|cve|port|service|analyse|analysis|"
        r"stand|status|scan.?job|letzter?.scan|wie.?(?:weit|lief|läuft|geht)|"
        r"fortschritt|progress|gefunden|entdeckt|ergebnis|offen|ports?)\b",
        re.IGNORECASE,
    )
    return bool(keywords.search(message))


# ─── Claude CLI Aufruf (--print Modus) ───────────────────────────


async def _ask_claude(prompt: str) -> str:
    """
    Ruft Claude CLI im --print Modus auf.
    Kein Agent-Modus — nur Textgenerierung.
    """
    claude_bin = shutil.which("claude")
    if not claude_bin:
        logger.warning("Claude CLI nicht gefunden — Fallback auf statische Antwort")
        return "Claude CLI ist gerade nicht verfügbar. Versuche es in ein paar Sekunden erneut."

    try:
        # Prompt kürzen damit Claude schneller antwortet
        short_prompt = prompt[:4000]

        # Claude CLI: --print + JSON output (schneller als Markdown)
        proc = await asyncio.create_subprocess_exec(
            claude_bin, "--print",
            "--output-format", "json",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=short_prompt.encode("utf-8")),
            timeout=120,
        )

        if proc.returncode == 0 and stdout:
            raw = stdout.decode("utf-8", errors="replace").strip()
            # JSON output parsen wenn möglich
            try:
                import json as _json
                data = _json.loads(raw)
                return data.get("result", data.get("content", raw))
            except Exception:
                return raw

        logger.error(
            "Claude CLI Fehler",
            returncode=proc.returncode,
            stderr=stderr.decode("utf-8", errors="replace")[:500],
        )
        return "Claude CLI ist gerade nicht verfügbar. Versuche es in ein paar Sekunden erneut."

    except asyncio.TimeoutError:
        # Prozess beenden falls er noch läuft
        try:
            proc.kill()
        except Exception:
            pass
        logger.warning("Claude CLI Timeout nach 120s")
        return (
            "Meine Antwort hat zu lange gedauert — entschuldige. "
            "Versuche eine kürzere Frage, z.B.:\n\n"
            "- **\"Prüfe Port 443 auf Techlogia.de\"**\n"
            "- **\"Welche Schwachstellen hat der SSH-Service?\"**\n"
            "- **\"Scanne scanme.nmap.org\"**\n"
            "- **\"Erstelle einen Report\"**"
        )
    except Exception as e:
        logger.error("Claude CLI fehlgeschlagen", error=str(e))
        return await _direct_db_answer()


async def _direct_db_answer() -> str:
    """Orchestrator-Status: Umfassender Überblick über alle Komponenten."""
    try:
        from uuid import UUID

        from src.shared.finding_repository import FindingRepository
        from src.shared.phase_repositories import (
            DiscoveredHostRepository,
            OpenPortRepository,
            ScanPhaseRepository,
        )
        from src.shared.repositories import ScanJobRepository
        from src.shared.types.models import ScanStatus

        db = await _get_db()
        scan_repo = ScanJobRepository(db)
        finding_repo = FindingRepository(db)
        phase_repo = ScanPhaseRepository(db)
        port_repo = OpenPortRepository(db)
        host_repo = DiscoveredHostRepository(db)

        all_scans = await scan_repo.list_all(limit=20)
        running = [s for s in all_scans if s.status == ScanStatus.RUNNING]
        completed = [s for s in all_scans if s.status == ScanStatus.COMPLETED]
        failed = [s for s in all_scans if s.status in (ScanStatus.FAILED, ScanStatus.EMERGENCY_KILLED)]

        parts = ["## 🤖 Orchestrator-Status\n"]

        # Laufende Scans mit Details
        if running:
            parts.append(f"### 🔵 {len(running)} laufende(r) Scan(s)\n")
            for s in running:
                elapsed = ""
                if s.started_at:
                    from datetime import datetime, timezone
                    delta = (datetime.now(timezone.utc) - s.started_at).total_seconds()
                    elapsed = f" — läuft seit {int(delta)}s"

                parts.append(f"**`{s.target}`** ({s.scan_type}){elapsed}")

                # Phasen des laufenden Scans
                phases = await phase_repo.list_by_scan(s.id)
                if phases:
                    for p in phases:
                        icon = {"completed": "✅", "running": "⏳", "failed": "❌", "pending": "⚪"}.get(p["status"], "?")
                        parts.append(
                            f"  {icon} Phase {p['phase_number']}: {p['name']} "
                            f"({p['status']}, {p['duration_seconds']:.0f}s) "
                            f"— {p['hosts_found']}H {p['ports_found']}P {p['findings_found']}F"
                        )
                parts.append("")
        else:
            parts.append("### Keine laufenden Scans\n")

        # Letzter abgeschlossener Scan mit Ergebnissen
        if completed:
            last = completed[0]
            parts.append(f"### Letzter abgeschlossener Scan\n")
            parts.append(f"**Ziel:** `{last.target}`")

            duration = ""
            if last.started_at and last.completed_at:
                delta = (last.completed_at - last.started_at).total_seconds()
                duration = f"{delta:.0f}s"
            parts.append(f"**Dauer:** {duration} | **Tokens:** {last.tokens_used}\n")

            # Hosts
            hosts = await host_repo.list_by_scan(last.id)
            if hosts:
                parts.append(f"**Hosts ({len(hosts)}):**")
                for h in hosts[:10]:
                    parts.append(f"- `{h['address']}` {h.get('hostname', '')}")

            # Ports
            ports = await port_repo.list_by_scan(last.id)
            if ports:
                parts.append(f"\n**Offene Ports ({len(ports)}):**")
                for p in ports[:10]:
                    parts.append(f"- `{p['host_address']}:{p['port']}/{p['protocol']}` {p['service']} {p['version']}")

            # Findings
            findings = await finding_repo.list_by_scan(last.id)
            if findings:
                sev: dict[str, int] = {}
                for f in findings:
                    sev[f.severity] = sev.get(f.severity, 0) + 1
                sev_text = ", ".join(f"**{v}x {k.upper()}**" for k, v in sev.items())
                parts.append(f"\n**Findings ({len(findings)}):** {sev_text}")
                for f in findings[:8]:
                    cve = f" ({f.cve_id})" if f.cve_id else ""
                    parts.append(f"- 🔴 [{f.severity.upper()}] {f.title}{cve}")
            else:
                parts.append("\nKeine Findings.")

            # Phasen
            phases = await phase_repo.list_by_scan(last.id)
            if phases:
                parts.append(f"\n**Phasen:**")
                for p in phases:
                    icon = {"completed": "✅", "failed": "❌"}.get(p["status"], "⚪")
                    parts.append(f"  {icon} {p['name']} ({p['duration_seconds']:.0f}s)")

        # Gesamtstatistik
        parts.append(f"\n---\n**Gesamt:** {len(all_scans)} Scans ({len(completed)} ✅ {len(running)} 🔵 {len(failed)} ❌)")

        return "\n".join(parts)
    except Exception as e:
        logger.error("Orchestrator-Status fehlgeschlagen", error=str(e))
        return f"Status konnte nicht geladen werden: `{e}`"


# ─── Scan im Hintergrund starten ─────────────────────────────────


async def _start_scan_from_chat(target: str, scan_id_ref: list[str]) -> None:
    """Erstellt und startet einen Scan-Job aus dem Chat heraus."""
    from src.shared.repositories import AuditLogRepository, ScanJobRepository
    from src.shared.types.models import AuditLogEntry, ScanJob

    db = await _get_db()
    scan_repo = ScanJobRepository(db)
    audit_repo = AuditLogRepository(db)

    # Scan-Job erstellen
    job = ScanJob(
        target=target,
        scan_type="recon",
        config={"ports": "1-1000", "source": "chat"},
    )
    await scan_repo.create(job)
    scan_id_ref.append(str(job.id))

    # Audit-Log
    await audit_repo.create(AuditLogEntry(
        action="scan.created",
        resource_type="scan_job",
        resource_id=str(job.id),
        details={"target": target, "source": "chat"},
        triggered_by="chat_user",
    ))

    # Scan im Hintergrund starten (gleiche Logik wie scan_routes.py)
    from src.api.scan_routes import _run_scan_background
    asyncio.create_task(
        _run_scan_background(str(job.id), target, "1-1000", 2)
    )

    logger.info("Scan aus Chat gestartet", scan_id=str(job.id), target=target)


# ─── Kontext aus DB fuer Findings-Fragen laden ───────────────────


async def _build_findings_context(scan_id: str | None = None) -> str:
    """Baut Kontext-String aus DB-Daten fuer Claude-Prompt.

    Enthält: Letzter Scan-Job, Phasen, Findings, offene Ports.
    """
    from uuid import UUID

    from src.shared.finding_repository import FindingRepository
    from src.shared.phase_repositories import OpenPortRepository, ScanPhaseRepository
    from src.shared.repositories import ScanJobRepository

    db = await _get_db()
    finding_repo = FindingRepository(db)
    scan_repo = ScanJobRepository(db)
    phase_repo = ScanPhaseRepository(db)
    port_repo = OpenPortRepository(db)

    context_parts = []

    # Scan-Job laden (spezifischer oder letzter)
    job = None
    if scan_id:
        job = await scan_repo.get_by_id(UUID(scan_id))
    else:
        # Letzten Scan finden
        all_scans = await scan_repo.list_all(limit=5)
        if all_scans:
            job = all_scans[0]
            scan_id = str(job.id)

    if job:
        duration = ""
        if job.started_at and job.completed_at:
            delta = (job.completed_at - job.started_at).total_seconds()
            duration = f", Dauer: {delta:.0f}s"

        context_parts.append(
            f"## Letzter Scan\n"
            f"- Ziel: {job.target}\n"
            f"- Status: {job.status}\n"
            f"- Typ: {job.scan_type}\n"
            f"- Tokens: {job.tokens_used}{duration}\n"
            f"- Erstellt: {job.created_at.isoformat()}"
        )

        # Phasen laden
        phases = await phase_repo.list_by_scan(UUID(scan_id))
        if phases:
            context_parts.append(f"\n## Phasen ({len(phases)}):")
            for p in phases:
                context_parts.append(
                    f"- Phase {p['phase_number']}: {p['name']} → {p['status']}"
                    f" ({p['duration_seconds']:.1f}s, {p['hosts_found']}H {p['ports_found']}P {p['findings_found']}F)"
                )

        # Offene Ports laden
        ports = await port_repo.list_by_scan(UUID(scan_id))
        if ports:
            context_parts.append(f"\n## Offene Ports ({len(ports)}):")
            for p in ports[:15]:
                context_parts.append(
                    f"- {p['host_address']}:{p['port']}/{p['protocol']} {p['service']} {p['version']}"
                )

        # Findings laden
        findings = await finding_repo.list_by_scan(UUID(scan_id))
    else:
        findings = await finding_repo.list_all(limit=50)

    if findings:
        # Severity-Zusammenfassung
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        context_parts.append(
            f"\n## Findings ({len(findings)}): "
            + ", ".join(f"{count}x {sev}" for sev, count in sev_counts.items())
        )
        for f in findings[:20]:
            cve = f" ({f.cve_id})" if f.cve_id else ""
            port = f":{f.target_port}" if f.target_port else ""
            context_parts.append(
                f"- [{f.severity.upper()} CVSS:{f.cvss_score}] {f.title} — {f.target_host}{port}{cve}"
            )
    else:
        context_parts.append("\nKeine Findings vorhanden.")

    return "\n".join(context_parts)


# ─── Hilfe-Text fuer allgemeine Nachrichten ───────────────────────

_HELP_RESPONSE = """Ich bin der SentinelClaw Security-Agent. Ich kann dir helfen mit:

**Scans starten:**
- "Scanne 10.10.10.0/24"
- "Teste example.com"
- "Pruefe 192.168.1.1"

**Ergebnisse analysieren:**
- "Was wurde gefunden?"
- "Zeige kritische Schwachstellen"
- "Zusammenfassung der Findings"

**System-Info:**
- "Status" — zeigt den System-Status
- "Hilfe" — zeigt diese Nachricht

Gib einfach ein Ziel ein, um einen Scan zu starten!"""


# ─── Endpoints ─────────────────────────────────────────────────────


@router.post("", response_model=ChatResponseModel)
async def send_chat_message(request: ChatRequest) -> ChatResponseModel:
    """
    Verarbeitet eine Chat-Nachricht und gibt eine Agent-Antwort zurueck.

    Erkennt automatisch:
    1. Scan-Befehle -> startet Scan im Hintergrund
    2. Fragen zu Findings -> laedt DB-Kontext, fragt Claude
    3. Sonstiges -> Hilfe-Text oder Claude-Antwort
    """
    message = request.message.strip()
    scan_id = request.scan_id

    if not message:
        return ChatResponseModel(response="Bitte gib eine Nachricht ein.")

    # Benutzer-Nachricht speichern (DB-Fehler ignorieren)
    try:
        await _save_message("user", message, scan_id=scan_id)
    except Exception as db_err:
        logger.warning("Chat-Nachricht konnte nicht gespeichert werden", error=str(db_err))

    try:
        return await _process_chat_message(message, scan_id)
    except Exception as e:
        logger.error("Chat-Verarbeitung fehlgeschlagen", error=str(e))
        return ChatResponseModel(
            response=f"Es ist ein Fehler aufgetreten. Bitte versuche es erneut.\n\n`{type(e).__name__}: {e}`",
            scan_started=False,
        )


async def _process_chat_message(message: str, scan_id: str | None) -> ChatResponseModel:
    """Interne Verarbeitung — ALLES geht durch Claude als echter Agent."""

    # 1. Scan-Befehl erkennen (einzige Sonderbehandlung)
    is_scan, target = _detect_scan_command(message)
    if is_scan and target:
        scan_id_ref: list[str] = []
        await _start_scan_from_chat(target, scan_id_ref)
        new_scan_id = scan_id_ref[0] if scan_id_ref else None

        response_text = (
            f"Ich starte jetzt einen Scan auf **{target}**. "
            f"Der Orchestrator führt 4 Phasen autonom durch:\n\n"
            f"1. 🔍 Host Discovery (nmap -sn)\n"
            f"2. 🔌 Port-Scan + Service-Erkennung (nmap -sV)\n"
            f"3. ⚠️ Vulnerability Assessment\n"
            f"4. 📊 Analyse & Bewertung\n\n"
            f"Du kannst den Live-Fortschritt verfolgen."
        )

        await _save_message("system", f"Scan gestartet: {target}",
                            scan_id=new_scan_id, message_type="scan_started")
        await _save_message("agent", response_text, scan_id=new_scan_id)

        return ChatResponseModel(response=response_text, scan_started=True, scan_id=new_scan_id)

    # 2. ALLES ANDERE: Claude als Orchestrator-Agent
    # Prompt so kurz wie möglich für schnelle Antwort
    prompt = f"Antworte kurz auf Deutsch als Security-Agent: {message}"

    response_text = await _ask_claude(prompt)
    try:
        await _save_message("agent", response_text, scan_id=scan_id)
    except Exception:
        pass

    return ChatResponseModel(response=response_text, scan_started=False)


@router.get("/history", response_model=list[ChatMessageOut])
async def get_chat_history(
    scan_id: str | None = Query(default=None, description="Scan-ID fuer gefilterten Verlauf"),
    limit: int = Query(default=100, ge=1, le=500, description="Maximale Anzahl Nachrichten"),
) -> list[ChatMessageOut]:
    """Gibt den Chat-Verlauf zurueck, optional gefiltert nach Scan-ID."""
    rows = await _load_history(scan_id=scan_id, limit=limit)
    return [
        ChatMessageOut(
            id=row["id"],
            scan_id=row["scan_id"],
            role=row["role"],
            content=row["content"],
            message_type=row["message_type"],
            created_at=row["created_at"],
        )
        for row in rows
    ]
