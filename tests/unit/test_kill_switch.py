"""
Unit-Tests für den Kill-Switch.

Prüft Singleton-Verhalten, Aktivierung, Irreversibilität und
die Metadaten (triggered_by, reason, activated_at).
Aus den E2E-Tests hierher verschoben für schnellere Ausführung.
"""

from unittest.mock import patch

from src.shared.kill_switch import KillSwitch


def _fresh_kill_switch() -> KillSwitch:
    """Gibt einen frischen Kill-Switch zurück (Reset für Tests)."""
    ks = KillSwitch()
    ks.reset()
    return ks


def test_singleton_liefert_gleiche_instanz():
    """Zwei Aufrufe von KillSwitch() liefern dasselbe Objekt."""
    ks_a = KillSwitch()
    ks_b = KillSwitch()
    assert ks_a is ks_b


def test_nicht_aktiv_nach_reset():
    """Nach reset() ist der Kill-Switch inaktiv."""
    ks = _fresh_kill_switch()
    assert not ks.is_active()
    assert ks.triggered_by == ""
    assert ks.reason == ""
    assert ks.activated_at is None


@patch.object(KillSwitch, "_stop_sandbox_container")
def test_aktivierung_setzt_flag(mock_stop):
    """activate() setzt das Kill-Flag und speichert Metadaten."""
    ks = _fresh_kill_switch()

    ks.activate(triggered_by="unit_test", reason="Testreason")

    assert ks.is_active()
    assert ks.triggered_by == "unit_test"
    assert ks.reason == "Testreason"
    assert ks.activated_at is not None
    mock_stop.assert_called_once()

    ks.reset()


@patch.object(KillSwitch, "_stop_sandbox_container")
def test_irreversibel_nach_aktivierung(mock_stop):
    """Zweite Aktivierung ändert weder Flag noch Metadaten."""
    ks = _fresh_kill_switch()

    ks.activate(triggered_by="erster", reason="Grund A")
    ks.activate(triggered_by="zweiter", reason="Grund B")

    # Erster Trigger bleibt erhalten
    assert ks.is_active()
    assert ks.triggered_by == "erster"
    assert ks.reason == "Grund A"
    # _stop_sandbox_container nur beim ersten Aufruf
    assert mock_stop.call_count == 1

    ks.reset()


@patch.object(KillSwitch, "_stop_sandbox_container")
def test_singleton_teilt_zustand(mock_stop):
    """Aktivierung über Instanz A ist über Instanz B sichtbar."""
    ks_a = _fresh_kill_switch()
    ks_b = KillSwitch()

    assert not ks_b.is_active()

    ks_a.activate(triggered_by="instanz_a", reason="Singleton-Test")
    assert ks_b.is_active()
    assert ks_b.triggered_by == "instanz_a"

    ks_a.reset()


@patch.object(KillSwitch, "_stop_sandbox_container")
def test_activated_at_ist_utc_datetime(mock_stop):
    """activated_at ist ein UTC-Datetime-Objekt."""
    from datetime import datetime, timezone

    ks = _fresh_kill_switch()
    ks.activate(triggered_by="zeit_test", reason="UTC-Prüfung")

    assert isinstance(ks.activated_at, datetime)
    assert ks.activated_at.tzinfo == timezone.utc

    ks.reset()
