"""
Echtzeit-Fortschrittsanzeige für SentinelClaw.

Callback-System das während Scans Live-Updates an die CLI
oder zukünftig an die WebSocket-UI sendet.
"""

import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class PhaseProgress:
    """Fortschritt einer einzelnen Phase."""

    phase_number: int
    name: str
    status: str = "pending"  # pending, running, completed, failed
    started_at: float | None = None
    hosts_found: int = 0
    ports_found: int = 0
    findings_found: int = 0
    message: str = ""


@dataclass
class ScanProgress:
    """Gesamtfortschritt eines Scans."""

    target: str
    total_phases: int = 4
    current_phase: int = 0
    phases: list[PhaseProgress] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)
    total_hosts: int = 0
    total_ports: int = 0
    total_findings: int = 0

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def percent(self) -> float:
        if self.total_phases == 0:
            return 0.0
        completed = sum(1 for p in self.phases if p.status == "completed")
        return (completed / self.total_phases) * 100


# Callback-Typ: Wird bei jedem Update aufgerufen
ProgressCallback = Callable[[ScanProgress], None]


class ProgressTracker:
    """Verfolgt und meldet den Scan-Fortschritt."""

    def __init__(self, target: str, callback: ProgressCallback | None = None) -> None:
        self._progress = ScanProgress(target=target)
        self._callback = callback or _default_cli_callback

    def start_phase(self, phase_number: int, name: str) -> None:
        """Markiert eine Phase als gestartet."""
        phase = PhaseProgress(
            phase_number=phase_number,
            name=name,
            status="running",
            started_at=time.monotonic(),
        )
        # Vorhandene Phase ersetzen oder neue anhängen
        existing = [p for p in self._progress.phases if p.phase_number == phase_number]
        if existing:
            idx = self._progress.phases.index(existing[0])
            self._progress.phases[idx] = phase
        else:
            self._progress.phases.append(phase)

        self._progress.current_phase = phase_number
        self._notify()

    def complete_phase(
        self,
        phase_number: int,
        hosts: int = 0,
        ports: int = 0,
        findings: int = 0,
        message: str = "",
    ) -> None:
        """Markiert eine Phase als abgeschlossen mit Ergebnissen."""
        for phase in self._progress.phases:
            if phase.phase_number == phase_number:
                phase.status = "completed"
                phase.hosts_found = hosts
                phase.ports_found = ports
                phase.findings_found = findings
                phase.message = message
                break

        self._progress.total_hosts += hosts
        self._progress.total_ports += ports
        self._progress.total_findings += findings
        self._notify()

    def fail_phase(self, phase_number: int, error: str) -> None:
        """Markiert eine Phase als fehlgeschlagen."""
        for phase in self._progress.phases:
            if phase.phase_number == phase_number:
                phase.status = "failed"
                phase.message = error
                break
        self._notify()

    def skip_phase(self, phase_number: int, name: str, reason: str) -> None:
        """Markiert eine Phase als übersprungen."""
        self._progress.phases.append(PhaseProgress(
            phase_number=phase_number,
            name=name,
            status="skipped",
            message=reason,
        ))
        self._notify()

    @property
    def progress(self) -> ScanProgress:
        return self._progress

    def _notify(self) -> None:
        """Ruft den Callback mit dem aktuellen Fortschritt auf."""
        if self._callback:
            self._callback(self._progress)


def _default_cli_callback(progress: ScanProgress) -> None:
    """Standard-Callback für CLI-Ausgabe: Live-Fortschritt im Terminal."""
    elapsed = progress.elapsed_seconds
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    # Letzte Phase bestimmen
    current = None
    for phase in progress.phases:
        if phase.status == "running":
            current = phase
            break

    # Fortschrittsbalken
    bar_width = 20
    filled = int(progress.percent / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    # Status-Zeile
    if current:
        status = f"Phase {current.phase_number}: {current.name}"
    else:
        completed = [p for p in progress.phases if p.status == "completed"]
        if completed:
            last = completed[-1]
            status = f"Phase {last.phase_number} abgeschlossen: {last.message}" if last.message else f"Phase {last.phase_number} abgeschlossen"
        else:
            status = "Vorbereitung..."

    # Ausgabe (überschreibt vorherige Zeile)
    line = (
        f"\r  {bar} {progress.percent:5.1f}%  "
        f"⏱ {minutes:02d}:{seconds:02d}  "
        f"🖥 {progress.total_hosts}H  "
        f"🔌 {progress.total_ports}P  "
        f"⚠ {progress.total_findings}V  "
        f"│ {status}"
    )

    # Zeile kürzen falls Terminal zu schmal
    sys.stderr.write(f"{line:<100}\n")
    sys.stderr.flush()
