"""Agent-Memory-Routen — Erinnerungen aus der Sandbox lesen und synchronisieren.

Ermöglicht das Abrufen der Agent-eigenen Memories aus
/sandbox/.claude/projects/-sandbox/memory/ und das Übernehmen
in die lokale workspace/MEMORY.md.
"""

from pathlib import Path

from fastapi import APIRouter, Request

from src.shared.auth import require_role
from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/nemoclaw", tags=["agent-memory"])

MEMORY_DIR = "/sandbox/.claude/projects/-sandbox/memory"


@router.get("/agent-memory")
async def get_agent_memory(request: Request) -> dict:
    """Liest die Agent-Memory-Dateien aus der Sandbox."""
    require_role(request, "analyst")

    from src.agents.openshell_executor import run_in_sandbox

    try:
        output, code = await run_in_sandbox(
            f"find {MEMORY_DIR} -name '*.md' "
            "-exec echo '===FILE:{}===' \\; -exec cat {} \\; 2>/dev/null",
            timeout=10,
        )
        if code != 0 or not output.strip():
            return {"memories": [], "raw": ""}

        memories = []
        for part in output.split("===FILE:"):
            if "===" not in part:
                continue
            path, content = part.split("===", 1)
            name = path.strip().split("/")[-1]
            if name == "MEMORY.md":
                continue
            memories.append({"name": name, "content": content.strip()})

        return {"memories": memories, "raw": output}
    except Exception as error:
        return {"memories": [], "raw": "", "error": str(error)}


@router.post("/pull-memory")
async def pull_agent_memory(request: Request) -> dict:
    """Holt Agent-Memories aus der Sandbox und schreibt sie in MEMORY.md."""
    require_role(request, "security_lead")

    from src.agents.openshell_executor import run_in_sandbox

    try:
        output, code = await run_in_sandbox(
            f"find {MEMORY_DIR} -name '*.md' ! -name 'MEMORY.md' "
            "-exec echo '### {}' \\; -exec cat {} \\; -exec echo '' \\; 2>/dev/null",
            timeout=10,
        )
    except Exception as error:
        return {"success": False, "message": f"Sandbox nicht erreichbar: {error}"}

    if code != 0 or not output.strip():
        return {"success": False, "message": "Keine Agent-Memories in der Sandbox gefunden."}

    agent_section = _clean_memory_output(output)

    workspace_dir = Path(__file__).resolve().parent.parent.parent / "workspace"
    memory_path = workspace_dir / "MEMORY.md"
    existing = memory_path.read_text(encoding="utf-8") if memory_path.exists() else ""

    # Agent-Abschnitt aktualisieren oder anhängen
    marker = "## Agent-Erinnerungen"
    if marker in existing:
        before = existing.split(marker)[0].rstrip()
        new_content = f"{before}\n\n{marker}\n\n{agent_section}\n"
    else:
        new_content = f"{existing.rstrip()}\n\n{marker}\n\n{agent_section}\n"

    memory_path.write_text(new_content, encoding="utf-8")
    logger.info("Agent-Memories in MEMORY.md übernommen")

    return {"success": True, "message": "Agent-Erinnerungen in MEMORY.md übernommen."}


def _clean_memory_output(output: str) -> str:
    """Entfernt Frontmatter und kürzt Pfade aus dem Memory-Output."""
    clean_lines: list[str] = []
    in_frontmatter = False

    for line in output.splitlines():
        if line.strip() == "---":
            in_frontmatter = not in_frontmatter
            continue
        if in_frontmatter:
            continue
        if line.startswith("### /sandbox/"):
            name = line.split("/")[-1]
            clean_lines.append(f"### {name}")
        else:
            clean_lines.append(line)

    return "\n".join(clean_lines).strip()
