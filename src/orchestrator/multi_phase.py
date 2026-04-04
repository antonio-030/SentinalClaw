"""
Multi-Phase Scan-Executor für den Orchestrator.

Führt jede Scan-Phase als separaten Claude-Agent-Aufruf aus.
Zwischen den Phasen werden Ergebnisse analysiert und die
nächste Phase mit den relevanten Informationen gefüttert.

Phase 1: Host Discovery (nmap -sn) → Welche Hosts sind aktiv?
Phase 2: Port-Scan (nmap -sV) → Welche Ports/Services laufen?
Phase 3: Vuln-Scan (nuclei) → Welche Schwachstellen gibt es?
"""

import time

from src.shared.logging_setup import get_logger
from src.agents.nemoclaw_runtime import (
    NemoClawRuntime,
    SANDBOX_CONTAINER,
    _build_cli_args,
    _invoke_claude_agent,
)
from src.agents.recon.agent import parse_agent_output
from src.agents.recon.result_types import ReconResult
from src.agents.token_tracker import TokenTracker

logger = get_logger(__name__)


async def run_phase(
    phase_name: str,
    system_prompt: str,
    user_prompt: str,
    max_turns: int = 5,
    timeout: float = 180,
    runtime: NemoClawRuntime | None = None,
) -> tuple[str, int]:
    """Führt eine einzelne Scan-Phase als Claude-Agent-Aufruf aus.

    Gibt den Textoutput und den geschätzten Token-Verbrauch zurück.
    """
    logger.info("Phase gestartet", phase=phase_name)
    start = time.monotonic()

    cli_args = _build_cli_args(
        system_prompt=system_prompt,
        max_turns=max_turns,
    )

    data = await _invoke_claude_agent(
        args=cli_args,
        user_prompt=user_prompt,
        timeout=timeout,
        runtime=runtime,
    )

    content = data.get("result", data.get("content", ""))
    tokens = data.get("num_turns", 0) * 5000  # Grobe Schätzung pro Turn
    duration = time.monotonic() - start

    logger.info(
        "Phase abgeschlossen",
        phase=phase_name,
        duration_s=round(duration, 1),
        content_length=len(content),
    )

    return content, tokens


async def run_multi_phase_scan(
    target: str,
    ports: str = "1-1000",
    allowed_targets: list[str] | None = None,
    max_escalation_level: int = 2,
    runtime: NemoClawRuntime | None = None,
) -> ReconResult:
    """Führt einen 3-Phasen-Scan mit separaten Agent-Aufrufen durch.

    Jede Phase bekommt die Ergebnisse der vorherigen Phase als Kontext.
    So kann der Agent gezielter arbeiten und die Token-Kosten sinken.
    """
    if allowed_targets is None:
        allowed_targets = [target]

    total_start = time.monotonic()
    token_tracker = TokenTracker(200_000)
    all_outputs: list[str] = []

    security_rules = (
        f"SECURITY RULES: ONLY scan {', '.join(allowed_targets)}. "
        f"NEVER scan other targets. Use docker exec {SANDBOX_CONTAINER} for ALL commands. "
        f"Max escalation: {max_escalation_level}."
    )

    # ── Phase 1: Host Discovery ────────────────────────────────
    logger.info("Phase 1: Host Discovery", target=target)

    phase1_system = (
        f"You are a network scanner. {security_rules}\n"
        f"Run ONLY this command and report the output:\n"
        f"docker exec {SANDBOX_CONTAINER} nmap -sn {target}\n"
        f"List all discovered hosts (IP + hostname if available)."
    )

    phase1_output, phase1_tokens = await run_phase(
        phase_name="Host Discovery",
        system_prompt=phase1_system,
        user_prompt=f"Discover active hosts in {target}",
        max_turns=3,
        timeout=120,
        runtime=runtime,
    )
    all_outputs.append(f"## Phase 1: Host Discovery\n{phase1_output}")
    token_tracker.add_usage(phase1_tokens, 0)

    # ── Phase 2: Port-Scan ─────────────────────────────────────
    logger.info("Phase 2: Port-Scan", target=target)

    phase2_system = (
        f"You are a port scanner. {security_rules}\n"
        f"Previous scan found these hosts:\n{phase1_output[:1000]}\n\n"
        f"Run this command and analyze the results:\n"
        f"docker exec {SANDBOX_CONTAINER} nmap -sV -sC -p {ports} {target}\n"
        f"Report: open ports, services, versions in a table."
    )

    phase2_output, phase2_tokens = await run_phase(
        phase_name="Port-Scan",
        system_prompt=phase2_system,
        user_prompt=f"Scan ports {ports} on {target} with service detection",
        max_turns=4,
        timeout=180,
        runtime=runtime,
    )
    all_outputs.append(f"## Phase 2: Port-Scan\n{phase2_output}")
    token_tracker.add_usage(phase2_tokens, 0)

    # ── Phase 3: Vulnerability Assessment ──────────────────────
    # Nur wenn Stufe >= 2 und offene Ports gefunden wurden
    phase3_output = ""
    if max_escalation_level >= 2 and ("open" in phase2_output.lower() or "PORT" in phase2_output):
        logger.info("Phase 3: Vulnerability Assessment", target=target)

        phase3_system = (
            f"You are a vulnerability scanner. {security_rules}\n"
            f"Previous port scan found:\n{phase2_output[:1500]}\n\n"
            f"Run a quick vulnerability assessment based on the discovered services.\n"
            f"Use: docker exec {SANDBOX_CONTAINER} nmap --script=default,vuln -p {ports} --script-timeout 30 {target}\n"
            f"If the scan takes too long, analyze the version information from Phase 2 instead.\n"
            f"For each service, check if the version has known CVEs.\n"
            f"Report vulnerabilities sorted by severity (CRITICAL, HIGH, MEDIUM, LOW).\n"
            f"Include CVE IDs. Provide risk assessment and 3 recommendations."
        )

        phase3_output, phase3_tokens = await run_phase(
            phase_name="Vulnerability Assessment",
            system_prompt=phase3_system,
            user_prompt=f"Check {target} for vulnerabilities",
            max_turns=4,
            timeout=180,
            runtime=runtime,
        )
        all_outputs.append(f"## Phase 3: Vulnerability Assessment\n{phase3_output}")
        token_tracker.add_usage(phase3_tokens, 0)
    else:
        all_outputs.append("## Phase 3: Übersprungen (keine offenen Ports oder Stufe < 2)")
        logger.info("Phase 3 übersprungen", reason="Keine offenen Ports oder Stufe < 2")

    # ── Ergebnisse zusammenführen ──────────────────────────────
    total_duration = time.monotonic() - total_start
    combined_output = "\n\n".join(all_outputs)

    result = parse_agent_output(
        target=target,
        agent_output=combined_output,
        duration=total_duration,
        tokens=token_tracker.total_used,
        steps=3 if phase3_output else 2,
    )

    logger.info(
        "Multi-Phase Scan abgeschlossen",
        target=target,
        hosts=result.total_hosts,
        ports=result.total_open_ports,
        vulns=result.total_vulnerabilities,
        duration_s=round(total_duration, 1),
        tokens=token_tracker.total_used,
    )

    return result
