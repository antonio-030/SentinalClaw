"""
Unit-Tests für den LLM-Daten-Sanitizer.

Prüft dass sensible Daten (Passwörter, API-Keys, E-Mails,
Kreditkarten, Private Keys) korrekt maskiert werden.
"""

from src.shared.sanitizer import LlmDataSanitizer, truncate_output

import pytest


def _sanitizer() -> LlmDataSanitizer:
    """Erstellt einen Sanitizer ohne Trunkierung für isolierte Pattern-Tests."""
    return LlmDataSanitizer()


def test_passwort_wird_maskiert():
    """Passwort-Zuweisungen werden durch [REDACTED] ersetzt."""
    sanitizer = _sanitizer()
    text = "password=GeheimesPasswort123"
    result = sanitizer.sanitize(text, truncate=False)
    assert "GeheimesPasswort123" not in result
    assert "[REDACTED]" in result


def test_api_key_anthropic_wird_maskiert():
    """Anthropic API-Keys (sk-ant-xxx) werden erkannt."""
    sanitizer = _sanitizer()
    text = "Token: sk-ant-api03-abcdef123456"
    result = sanitizer.sanitize(text, truncate=False)
    assert "sk-ant-api03-abcdef123456" not in result
    assert "[REDACTED]" in result


def test_generischer_api_key_wird_maskiert():
    """Generische api_key=xxx Zuweisungen werden erkannt."""
    sanitizer = _sanitizer()
    text = "api_key=AKIAIOSFODNN7EXAMPLE"
    result = sanitizer.sanitize(text, truncate=False)
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "[REDACTED]" in result


def test_email_wird_maskiert():
    """E-Mail-Adressen werden durch [REDACTED] ersetzt."""
    sanitizer = _sanitizer()
    text = "Kontakt: admin@example.com und user@test.org"
    result = sanitizer.sanitize(text, truncate=False)
    assert "admin@example.com" not in result
    assert "user@test.org" not in result


def test_kreditkarte_wird_maskiert():
    """Kreditkartennummern (4x4 Ziffern) werden erkannt."""
    sanitizer = _sanitizer()
    text = "Karte: 4111 2222 3333 4444"
    result = sanitizer.sanitize(text, truncate=False)
    assert "4111 2222 3333 4444" not in result
    assert "[REDACTED]" in result


def test_kreditkarte_mit_bindestrich():
    """Kreditkartennummern mit Bindestrich werden erkannt."""
    sanitizer = _sanitizer()
    text = "CC: 4111-2222-3333-4444"
    result = sanitizer.sanitize(text, truncate=False)
    assert "4111-2222-3333-4444" not in result


def test_private_key_wird_maskiert():
    """RSA Private Keys werden vollständig entfernt."""
    sanitizer = _sanitizer()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBog...Basis64Daten...\n-----END RSA PRIVATE KEY-----"
    result = sanitizer.sanitize(text, truncate=False)
    assert "PRIVATE KEY" not in result
    assert "Basis64Daten" not in result


def test_normaler_text_bleibt_unveraendert():
    """Text ohne sensible Daten bleibt identisch."""
    sanitizer = _sanitizer()
    text = "Scan auf Port 80 abgeschlossen. 3 Hosts gefunden."
    result = sanitizer.sanitize(text, truncate=False)
    assert result == text


def test_leerer_text():
    """Leerer String wird unverändert zurückgegeben."""
    sanitizer = _sanitizer()
    assert sanitizer.sanitize("") == ""


def test_truncate_output_kuerzt_langen_text():
    """Texte über max_length werden gekürzt und mit Hinweis versehen."""
    langer_text = "A" * 300
    result = truncate_output(langer_text, max_length=200)
    assert len(result) <= 200
    assert "gekürzt" in result


def test_truncate_output_kurzer_text_unveraendert():
    """Kurze Texte werden nicht verändert."""
    text = "kurz"
    assert truncate_output(text, max_length=200) == text


def test_max_length_unter_100_wirft_fehler():
    """max_length unter 100 ist ungültig."""
    with pytest.raises(ValueError, match="mindestens 100"):
        LlmDataSanitizer(max_length=50)


def test_add_pattern_erweitert_erkennung():
    """Benutzerdefinierte Muster werden korrekt angewendet."""
    sanitizer = _sanitizer()
    sanitizer.add_pattern("custom_token", r"ghp_[A-Za-z0-9]{36}")

    text = "GitHub: ghp_ABCDEFghijklmnop1234567890abcdefghij"
    result = sanitizer.sanitize(text, truncate=False)
    assert "ghp_" not in result
    assert "[REDACTED]" in result
