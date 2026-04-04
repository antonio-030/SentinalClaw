"""
LLM-Daten-Sanitizer für SentinelClaw.

Filtert sensible Daten BEVOR sie an das LLM gesendet werden.
Erkennt Passwörter, API-Keys, Private Keys, Passwort-Hashes,
E-Mail-Adressen und Kreditkartennummern. Zusätzlich wird die
Ausgabe auf eine konfigurierbare Maximallänge gekürzt.
"""

import re
from dataclasses import dataclass

from src.shared.logging_setup import get_logger

logger = get_logger(__name__)

# Ersetzungstext für alle erkannten sensiblen Daten
_REDACTED: str = "[REDACTED]"

# Standard-Maximallänge für die Ausgabetrunkierung
_DEFAULT_MAX_LENGTH: int = 5000

# Suffix das bei gekürzten Texten angehängt wird
_TRUNCATION_SUFFIX: str = "\n\n[... Ausgabe gekürzt — {removed} Zeichen entfernt ...]"


# --- Vorkompilierte Regex-Pattern für maximale Performance ---

@dataclass(frozen=True, slots=True)
class _SanitizationPattern:
    """Einzelnes Bereinigungsmuster mit Name und kompiliertem Regex.

    Attribute:
        name: Bezeichnung des Musters für Logging-Zwecke.
        regex: Vorkompiliertes Regex-Objekt.
        replacement: Ersetzungstext (Standard: [REDACTED]).
    """

    name: str
    regex: re.Pattern[str]
    replacement: str = _REDACTED


def _build_patterns() -> tuple[_SanitizationPattern, ...]:
    """Erstellt alle Bereinigungsmuster als vorkompilierte Regexe.

    Returns:
        Tuple mit allen Bereinigungsmustern in Anwendungsreihenfolge.
        Mehrzeilige Muster (Private Keys) kommen zuerst.
    """
    return (
        # --- Private Keys (mehrzeilig, deshalb zuerst) ---
        _SanitizationPattern(
            name="private_key",
            regex=re.compile(
                r"-----BEGIN\s[\w\s]*PRIVATE\sKEY-----"
                r"[\s\S]*?"
                r"-----END\s[\w\s]*PRIVATE\sKEY-----",
                re.MULTILINE,
            ),
        ),

        # --- Passwörter (password=xxx, passwd=xxx, pwd=xxx) ---
        _SanitizationPattern(
            name="password_assignment",
            regex=re.compile(
                r"(?i)"
                r"(?:password|passwd|pwd)"
                r"\s*[=:]\s*"
                r"""(?:["']?)"""
                r"(\S+)"
                r"""(?:["']?)""",
            ),
            replacement=r"password=[REDACTED]",
        ),

        # --- API-Keys: Anthropic (sk-ant-xxx) ---
        _SanitizationPattern(
            name="anthropic_api_key",
            regex=re.compile(
                r"sk-ant-[A-Za-z0-9_-]{5,}",
            ),
        ),

        # --- API-Keys: Generisch (api_key=xxx, api-key=xxx, apikey=xxx) ---
        _SanitizationPattern(
            name="generic_api_key",
            regex=re.compile(
                r"(?i)"
                r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)"
                r"\s*[=:]\s*"
                r"""(?:["']?)"""
                r"([A-Za-z0-9_\-/.+]{8,})"
                r"""(?:["']?)""",
            ),
            replacement=r"api_key=[REDACTED]",
        ),

        # --- Passwort-Hashes ($algorithmus$salt$hash) ---
        _SanitizationPattern(
            name="password_hash",
            regex=re.compile(
                r"\$(?:1|2[aby]?|5|6|argon2[id]?|bcrypt|scrypt|pbkdf2)"
                r"\$[^\s$]+"
                r"\$[^\s$]+",
            ),
        ),

        # --- E-Mail-Adressen ---
        _SanitizationPattern(
            name="email_address",
            regex=re.compile(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ),
        ),

        # --- Kreditkartennummern (4 Gruppen à 4 Ziffern) ---
        _SanitizationPattern(
            name="credit_card",
            regex=re.compile(
                r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b",
            ),
        ),
    )


# Muster werden einmal beim Modulimport kompiliert
_PATTERNS: tuple[_SanitizationPattern, ...] = _build_patterns()


class LlmDataSanitizer:
    """Bereinigt Texte von sensiblen Daten bevor sie ans LLM gehen.

    Wendet alle definierten Muster an und ersetzt Treffer durch
    [REDACTED]. Kann optional die Ausgabe auf eine Maximallänge kürzen.

    Attribute:
        max_length: Maximale Textlänge nach Bereinigung. Wird nur
            angewendet wenn truncate=True bei sanitize() übergeben wird.
            Standard: 5000 Zeichen.
    """

    def __init__(self, max_length: int = _DEFAULT_MAX_LENGTH) -> None:
        """Initialisiert den Sanitizer mit konfigurierbarer Maximallänge.

        Args:
            max_length: Maximale Textlänge für Trunkierung.
                Muss mindestens 100 sein.

        Raises:
            ValueError: Wenn max_length kleiner als 100 ist.
        """
        if max_length < 100:
            raise ValueError(
                f"max_length muss mindestens 100 sein, war: {max_length}"
            )
        self.max_length: int = max_length
        self._patterns: tuple[_SanitizationPattern, ...] = _PATTERNS

    def sanitize(self, text: str, *, truncate: bool = True) -> str:
        """Entfernt alle sensiblen Daten aus dem Text.

        Wendet alle Bereinigungsmuster sequentiell an. Optional wird
        die Ausgabe danach auf max_length gekürzt.

        Args:
            text: Eingabetext der bereinigt werden soll.
            truncate: Ob die Ausgabe auf max_length gekürzt werden soll.
                Standard: True.

        Returns:
            Bereinigter Text mit [REDACTED] an Stelle sensibler Daten.
        """
        if not text:
            return text

        result: str = text
        total_matches: int = 0

        for pattern in self._patterns:
            result, count = pattern.regex.subn(pattern.replacement, result)
            if count > 0:
                total_matches += count
                logger.debug(
                    "Sensible Daten entfernt",
                    pattern=pattern.name,
                    count=count,
                )

        if total_matches > 0:
            logger.info(
                "Sanitizer-Zusammenfassung",
                total_redacted=total_matches,
                input_length=len(text),
                output_length=len(result),
            )

        if truncate:
            result = truncate_output(result, self.max_length)

        return result

    def add_pattern(
        self,
        name: str,
        pattern: str,
        replacement: str = _REDACTED,
        *,
        flags: re.RegexFlag = re.NOFLAG,
    ) -> None:
        """Fügt ein benutzerdefiniertes Bereinigungsmuster hinzu.

        Erlaubt es, projektspezifische Muster zur Laufzeit zu ergänzen.

        Args:
            name: Bezeichnung des Musters für Logging.
            pattern: Regex-Pattern als String.
            replacement: Ersetzungstext. Standard: [REDACTED].
            flags: Optionale Regex-Flags.
        """
        new_pattern = _SanitizationPattern(
            name=name,
            regex=re.compile(pattern, flags),
            replacement=replacement,
        )
        self._patterns = (*self._patterns, new_pattern)
        logger.info(
            "Benutzerdefiniertes Muster hinzugefügt",
            pattern_name=name,
        )


def truncate_output(text: str, max_length: int = _DEFAULT_MAX_LENGTH) -> str:
    """Kürzt einen Text auf die angegebene Maximallänge.

    Schneidet am Ende ab und fügt einen Hinweis an, wie viele Zeichen
    entfernt wurden. Kurze Texte bleiben unverändert.

    Args:
        text: Text der gekürzt werden soll.
        max_length: Maximale Zeichenanzahl. Standard: 5000.

    Returns:
        Originaler Text wenn kürzer als max_length,
        sonst gekürzter Text mit Hinweis-Suffix.

    Raises:
        ValueError: Wenn max_length kleiner als 100 ist.
    """
    if max_length < 100:
        raise ValueError(
            f"max_length muss mindestens 100 sein, war: {max_length}"
        )

    if len(text) <= max_length:
        return text

    removed: int = len(text) - max_length
    suffix: str = _TRUNCATION_SUFFIX.format(removed=removed)
    truncated: str = text[: max_length - len(suffix)] + suffix

    logger.debug(
        "Ausgabe gekürzt",
        original_length=len(text),
        truncated_length=len(truncated),
        removed_chars=removed,
    )

    return truncated
