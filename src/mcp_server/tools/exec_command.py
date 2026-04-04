"""
MCP-Tool: exec_command — Freie Befehlsausführung in der Sandbox.

Führt einen Befehl im Sandbox-Container aus. NUR erlaubte
Binaries (Allowlist). Scope-Check auf extrahierte Ziele.
"""

import re

from src.sandbox.executor import ExecutionResult, SandboxExecutor
from src.shared.constants.defaults import ALLOWED_SANDBOX_BINARIES
from src.shared.logging_setup import get_logger
from src.shared.scope_validator import ScopeValidator
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


async def run_exec_command(
    command_parts: list[str],
    timeout: int = 60,
    scope: PentestScope | None = None,
    executor: SandboxExecutor | None = None,
    scope_validator: ScopeValidator | None = None,
) -> ExecutionResult:
    """Führt einen Befehl in der Sandbox aus.

    Strenge Validierung:
    - Binary muss in der Allowlist sein
    - Ziel-IPs/Domains werden extrahiert und gegen Scope geprüft
    - Timeout ist Pflicht
    """
    if not command_parts:
        raise ValueError("Kein Befehl angegeben")

    binary = command_parts[0]

    # Binary gegen Allowlist prüfen
    if binary not in ALLOWED_SANDBOX_BINARIES:
        raise PermissionError(
            f"Binary '{binary}' nicht erlaubt. "
            f"Nur: {', '.join(sorted(ALLOWED_SANDBOX_BINARIES))}"
        )

    # Ziel-IPs/Domains aus dem Befehl extrahieren und Scope prüfen
    if scope and scope_validator:
        targets = _extract_targets_from_args(command_parts[1:])
        for target in targets:
            result = scope_validator.validate(
                target=target, port=None, tool_name=binary, scope=scope,
            )
            if not result.allowed:
                raise PermissionError(
                    f"Scope-Verletzung für Ziel '{target}': {result.reason}"
                )

    logger.info(
        "Freier Befehl in Sandbox",
        binary=binary,
        arg_count=len(command_parts) - 1,
        timeout=timeout,
    )

    sandbox = executor or SandboxExecutor()
    return await sandbox.execute(command_parts, timeout=timeout)


def _extract_targets_from_args(args: list[str]) -> list[str]:
    """Extrahiert mögliche Scan-Ziele (IPs/Domains) aus Befehlsargumenten.

    Erkennt IPv4-Adressen, CIDR-Ranges und Domain-ähnliche Strings.
    Flags und Flag-Werte werden ignoriert.
    """
    targets: list[str] = []

    # Regex für IPv4, IPv4/CIDR und Domains
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$")
    domain_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")

    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue

        # Flags überspringen (beginnen mit -)
        if arg.startswith("-"):
            # Flags mit Wert (z.B. -p 80) → nächstes Argument überspringen
            if arg in {"-p", "-oX", "-oN", "-oG", "-t", "-u", "--top-ports", "-severity"}:
                skip_next = True
            continue

        # Prüfe ob das Argument wie ein Ziel aussieht
        # Komma-separierte Ziele aufteilen
        for part in arg.split(","):
            part = part.strip()
            if ip_pattern.match(part) or domain_pattern.match(part):
                targets.append(part)

    return targets
