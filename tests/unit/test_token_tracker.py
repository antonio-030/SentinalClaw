"""
Unit-Tests für den Token-Budget-Tracker.

Prüft Verbrauchszählung, Warnung bei 80%, Budget-Überschreitung
bei 100% und die Summary-Ausgabe.
"""

from src.agents.token_tracker import TokenTracker, WARN_THRESHOLD


def test_initialer_zustand():
    """Neuer Tracker hat 0 Verbrauch und volles Budget."""
    tracker = TokenTracker(budget=10000)
    assert tracker.total_used == 0
    assert tracker.remaining == 10000
    assert tracker.percent_used == 0.0
    assert not tracker.is_budget_exceeded()
    assert not tracker.should_warn()


def test_add_usage_zaehlt_korrekt():
    """Prompt- und Completion-Tokens werden addiert."""
    tracker = TokenTracker(budget=10000)
    tracker.add_usage(prompt_tokens=500, completion_tokens=300)
    assert tracker.total_used == 800
    assert tracker.remaining == 9200


def test_mehrere_add_usage_kumulativ():
    """Mehrere Aufrufe werden kumuliert."""
    tracker = TokenTracker(budget=1000)
    tracker.add_usage(100, 50)
    tracker.add_usage(200, 100)
    tracker.add_usage(50, 25)
    assert tracker.total_used == 525
    assert tracker.remaining == 475


def test_warnung_bei_80_prozent():
    """should_warn() gibt True ab 80% Verbrauch."""
    tracker = TokenTracker(budget=1000)
    tracker.add_usage(700, 0)
    assert not tracker.should_warn()

    tracker.add_usage(100, 0)  # Jetzt bei 80%
    assert tracker.should_warn()


def test_budget_ueberschritten_bei_100_prozent():
    """is_budget_exceeded() gibt True bei >= 100% Verbrauch."""
    tracker = TokenTracker(budget=1000)
    tracker.add_usage(500, 400)
    assert not tracker.is_budget_exceeded()

    tracker.add_usage(50, 50)  # Genau 1000 = 100%
    assert tracker.is_budget_exceeded()


def test_budget_ueberschritten_ueber_100_prozent():
    """Verbrauch kann das Budget übersteigen."""
    tracker = TokenTracker(budget=1000)
    tracker.add_usage(800, 500)  # 1300 > 1000
    assert tracker.is_budget_exceeded()
    assert tracker.remaining == 0  # Nicht negativ
    assert tracker.percent_used > 1.0


def test_percent_used_berechnung():
    """Prozentualer Verbrauch wird korrekt berechnet."""
    tracker = TokenTracker(budget=2000)
    tracker.add_usage(500, 500)
    assert tracker.percent_used == 0.5


def test_summary_enthaelt_alle_felder():
    """summary() gibt ein Dictionary mit allen relevanten Feldern zurück."""
    tracker = TokenTracker(budget=5000)
    tracker.add_usage(1000, 500)

    info = tracker.summary()
    assert info["prompt_tokens"] == 1000
    assert info["completion_tokens"] == 500
    assert info["total_used"] == 1500
    assert info["budget"] == 5000
    assert info["remaining"] == 3500
    assert info["percent_used"] == 30.0


def test_budget_null_keine_division_durch_null():
    """Budget 0 führt nicht zu ZeroDivisionError."""
    tracker = TokenTracker(budget=0)
    tracker.add_usage(100, 50)
    assert tracker.percent_used == 0.0
    assert tracker.remaining == 0


def test_warn_threshold_ist_80_prozent():
    """Die Warnschwelle ist als Konstante auf 0.8 definiert."""
    assert WARN_THRESHOLD == 0.8
