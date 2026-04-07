"""
Recon-Agent — Spezialisierter Agent für Netzwerk-Reconnaissance.

Führt autonom Host Discovery, Port-Scanning und Vulnerability-Scanning
auf einem Ziel durch. Nutzt die NemoClaw-Runtime (OpenClaw in Sandbox).
Entspricht FA-02 im Lastenheft.
"""

import time

from src.agents.nemoclaw_runtime import NemoClawRuntime
from src.agents.recon.parser import parse_agent_output
from src.agents.recon.prompts import build_scan_system_prompt
from src.agents.recon.result_types import ReconResult
from src.agents.token_tracker import TokenBudgetExceededError, TokenTracker
from src.shared.config import get_settings
from src.shared.logging_setup import get_logger
from src.shared.types.scope import PentestScope

logger = get_logger(__name__)


class ReconAgent:
    """Spezialisierter Reconnaissance-Agent.

    Nimmt ein Scan-Ziel entgegen und lässt die NemoClaw-Runtime
    den Scan autonom durchführen. OpenClaw übernimmt den
    Agent-Loop: Plant → führt Tools aus → Analysiert.
    """

    def __init__(self, runtime: NemoClawRuntime, scope: PentestScope) -> None:
        self._runtime = runtime
        self._scope = scope
        self._settings = get_settings()

    async def run_reconnaissance(self, target: str, ports: str = "1-1000") -> ReconResult:
        """Führt einen vollständigen Recon-Scan auf dem Ziel durch."""
        start_time = time.monotonic()
        token_tracker = TokenTracker(self._settings.llm_max_tokens_per_scan)

        logger.info("Recon-Agent gestartet", target=target, ports=ports)

        system_prompt = build_scan_system_prompt(
            target=target,
            allowed_targets=self._scope.targets_include,
            max_escalation_level=self._scope.max_escalation_level,
            ports=ports,
        )

        user_message = (
            f"Führe einen vollständigen Reconnaissance-Scan auf {target} durch. "
            f"Alle 3 Phasen: Host Discovery, Port-Scan (Ports {ports}), Vulnerability-Scan. "
            f"Gib am Ende eine strukturierte Zusammenfassung."
        )

        agent_result = await self._runtime.run_agent(
            system_prompt=system_prompt,
            user_message=user_message,
            max_iterations=15,
        )

        try:
            token_tracker.add_usage(
                agent_result.total_prompt_tokens,
                agent_result.total_completion_tokens,
            )
        except TokenBudgetExceededError:
            logger.warning(
                "Token-Budget erschöpft — verwende bisherige Ergebnisse",
                target=target,
                used=token_tracker.total_used,
            )

        duration = time.monotonic() - start_time

        recon_result = parse_agent_output(
            target=target,
            agent_output=agent_result.final_output,
            duration=duration,
            tokens=token_tracker.total_used,
            steps=agent_result.steps_taken,
        )

        logger.info(
            "Recon-Agent abgeschlossen",
            target=target,
            hosts=recon_result.total_hosts,
            ports=recon_result.total_open_ports,
            vulns=recon_result.total_vulnerabilities,
            duration_s=round(duration, 1),
            tokens=token_tracker.total_used,
        )

        return recon_result
