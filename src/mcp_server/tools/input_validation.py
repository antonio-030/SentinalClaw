"""
Input-Validierung für MCP-Tool-Parameter.

Jeder externe Input wird hier validiert bevor er an die
Sandbox weitergereicht wird. Keine Ausnahmen.
"""

import ipaddress
import re

from src.shared.constants.defaults import ALLOWED_NMAP_FLAGS, ALLOWED_NUCLEI_TEMPLATES


def validate_target(target: str) -> str:
    """Validiert und bereinigt ein Scan-Ziel.

    Akzeptiert: IPv4, IPv6, CIDR-Notation, FQDN.
    Lehnt ab: Leere Strings, Sonderzeichen, Shell-Metazeichen.
    """
    target = target.strip()

    if not target:
        raise ValueError("Scan-Ziel darf nicht leer sein")

    # Shell-Metazeichen blockieren (Command Injection Prevention)
    dangerous_chars = set(";|&$`(){}[]!><'\"\\")
    if any(char in target for char in dangerous_chars):
        raise ValueError(f"Scan-Ziel enthält ungültige Zeichen: {target}")

    # Komma-separierte Ziele sind erlaubt (z.B. "10.10.10.3,10.10.10.5")
    targets = [t.strip() for t in target.split(",")]
    for single_target in targets:
        if not _is_valid_single_target(single_target):
            raise ValueError(f"Ungültiges Scan-Ziel: '{single_target}'")

    return target


def _is_valid_single_target(target: str) -> bool:
    """Prüft ob ein einzelnes Ziel gültig ist (IP, CIDR oder Domain)."""
    # IPv4/IPv6 Adresse
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # CIDR-Notation
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # FQDN (Domain)
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    return bool(domain_pattern.match(target))


def validate_ports(ports: str) -> str:
    """Validiert einen Port-Range-String.

    Akzeptiert: "80", "80,443", "1-1000", "80,443,8000-8100"
    Lehnt ab: Negative Ports, > 65535, ungültige Formate.
    """
    ports = ports.strip()
    if not ports:
        raise ValueError("Port-Range darf nicht leer sein")

    # Nur erlaubte Zeichen: Ziffern, Komma, Bindestrich
    if not re.match(r"^[\d,\-\s]+$", ports):
        raise ValueError(f"Port-Range enthält ungültige Zeichen: {ports}")

    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            range_parts = part.split("-", 1)
            if len(range_parts) != 2:
                raise ValueError(f"Ungültiger Port-Range: {part}")
            start, end = int(range_parts[0]), int(range_parts[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Port-Range außerhalb 1-65535: {part}")
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Port außerhalb 1-65535: {port}")

    return ports


def validate_nmap_flags(flags: list[str]) -> list[str]:
    """Validiert nmap-Flags gegen die Allowlist.

    Nur explizit erlaubte Flags werden durchgelassen.
    Blockiert gefährliche Flags wie --script=, -iL, etc.
    """
    validated: list[str] = []
    for flag in flags:
        flag = flag.strip()
        if not flag:
            continue

        # Flag muss in der Allowlist sein
        # Für Flags mit Wert (z.B. -p 80): nur den Flag-Teil prüfen
        flag_base = flag.split(" ")[0] if " " in flag else flag
        flag_base = flag.split("=")[0] if "=" in flag else flag_base

        if flag_base in ALLOWED_NMAP_FLAGS:
            validated.append(flag)
        else:
            raise ValueError(
                f"nmap-Flag '{flag}' ist nicht erlaubt. "
                f"Erlaubt: {', '.join(sorted(ALLOWED_NMAP_FLAGS))}"
            )

    return validated


def validate_nuclei_templates(templates: list[str]) -> list[str]:
    """Validiert nuclei-Template-Kategorien gegen die Allowlist."""
    validated: list[str] = []
    for template in templates:
        template = template.strip().lower()
        if template in ALLOWED_NUCLEI_TEMPLATES:
            validated.append(template)
        else:
            raise ValueError(
                f"Nuclei-Template '{template}' ist nicht erlaubt. "
                f"Erlaubt: {', '.join(sorted(ALLOWED_NUCLEI_TEMPLATES))}"
            )
    return validated
