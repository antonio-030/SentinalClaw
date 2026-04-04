"""
Unit-Tests für die Scan-Profile.

Prüft get_profile(), list_profiles(), list_profile_names()
und den Fehlerfall bei ungültigem Profilnamen.
"""

import pytest

from src.shared.scan_profiles import (
    ScanProfile,
    get_profile,
    list_profile_names,
    list_profiles,
)


def test_get_profile_standard():
    """Standard-Profil wird korrekt geladen."""
    profile = get_profile("standard")
    assert isinstance(profile, ScanProfile)
    assert profile.name == "Standard Recon"
    assert profile.ports == "1-1000"
    assert profile.max_escalation_level == 2


def test_get_profile_quick():
    """Quick-Profil überspringt Vuln-Scan."""
    profile = get_profile("quick")
    assert profile.skip_vuln_scan is True
    assert profile.max_escalation_level == 1


def test_get_profile_full():
    """Full-Profil scannt alle 65535 Ports."""
    profile = get_profile("full")
    assert profile.ports == "1-65535"
    assert profile.nmap_extra_flags == ["-T4"]


def test_get_profile_case_insensitive():
    """Profilname wird case-insensitiv aufgelöst."""
    profile = get_profile("Web")
    assert profile.name == "Web Application"


def test_get_profile_ungueltig_wirft_fehler():
    """Ungültiger Profilname wirft ValueError mit Hinweis."""
    with pytest.raises(ValueError, match="Unbekanntes Profil"):
        get_profile("nonexistent")


def test_get_profile_fehler_zeigt_verfuegbare():
    """Fehlermeldung enthält die Namen aller verfügbaren Profile."""
    with pytest.raises(ValueError, match="quick"):
        get_profile("invalid_profile")


def test_list_profiles_gibt_alle_zurueck():
    """list_profiles() gibt mindestens 7 Profile zurück."""
    profiles = list_profiles()
    assert len(profiles) >= 7
    assert all(isinstance(p, ScanProfile) for p in profiles)


def test_list_profile_names_enthaelt_bekannte():
    """list_profile_names() enthält die Standardprofile."""
    names = list_profile_names()
    expected = {"quick", "standard", "full", "web", "database", "infrastructure", "stealth"}
    assert expected.issubset(set(names))


def test_profile_ist_frozen():
    """ScanProfile-Objekte sind unveränderlich (frozen dataclass)."""
    profile = get_profile("standard")
    with pytest.raises(AttributeError):
        profile.name = "Manipulated"


def test_stealth_profil_hat_timing_flags():
    """Stealth-Profil nutzt T1-Timing und Pn-Flag."""
    profile = get_profile("stealth")
    assert "-T1" in profile.nmap_extra_flags
    assert "-Pn" in profile.nmap_extra_flags
    assert profile.skip_vuln_scan is True


def test_database_profil_ports():
    """Datenbank-Profil enthält die wichtigsten DB-Ports."""
    profile = get_profile("database")
    # MySQL, PostgreSQL und Redis Ports muessen enthalten sein
    assert "3306" in profile.ports
    assert "5432" in profile.ports
    assert "6379" in profile.ports
