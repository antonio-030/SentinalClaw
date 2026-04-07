// Beschreibungsbox mit Doku-Links für eine Einstellungskategorie

// ── Kategorie-Beschreibungen + Doku-Links ──────────────────────────

interface CategoryInfo {
  title: string;
  description: string;
  links?: Array<{ url: string; label: string }>;
}

const CATEGORY_INFO: Record<string, CategoryInfo> = {
  agent: {
    title: 'Agent-Konfiguration',
    description: 'Steuert was der AI-Agent darf: erlaubte/blockierte Binaries, maximale Eskalationsstufe, '
      + 'Genehmigungsschwelle für gefährliche Tools, verbotene Aktionen (DoS, Ransomware), und ob der Agent selbst Tools installieren darf. '
      + 'Änderungen wirken sofort auf den nächsten Agent-Aufruf.',
  },
  nemoclaw: {
    title: 'NemoClaw / OpenShell Sandbox',
    description: 'Konfiguration der NemoClaw-Sandbox in der der Agent isoliert läuft. '
      + 'Diese Einstellungen basieren auf den NVIDIA NemoClaw Security Best Practices: '
      + 'Prozess-Limits (Fork-Bomb-Schutz), Read-Only Dateisystem, Capability-Drops, '
      + 'Credential-Isolation (API-Keys werden nie an die Sandbox übergeben), und Netzwerk-Policy.',
    links: [
      { url: 'https://docs.nvidia.com/nemoclaw/latest/security/best-practices.html', label: 'Security Best Practices' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/deployment/sandbox-hardening.html', label: 'Sandbox Hardening' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/network-policy/customize-network-policy.html', label: 'Network Policy' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/reference/commands.html', label: 'CLI-Referenz' },
      { url: 'https://docs.nvidia.com/nemoclaw/latest/inference/inference-options.html', label: 'Inference-Provider' },
    ],
  },
  security: {
    title: 'Authentifizierung & Sicherheit',
    description: 'JWT-Token-Lebensdauer, Cookie-Konfiguration, Session-Inaktivitäts-Timeout, '
      + 'MFA-Einstellungen und API-Rate-Limits. Alle Authentifizierungsparameter die bestimmen '
      + 'wie lange Sessions gültig sind und wie viele Anfragen pro Minute erlaubt sind.',
  },
  sandbox: {
    title: 'Docker Sandbox-Ressourcen',
    description: 'Ressourcen-Limits für den Docker-Sandbox-Container: Arbeitsspeicher (RAM), '
      + 'CPU-Kerne, maximale Prozessanzahl (PID-Limit) und Timeout. Diese Werte begrenzen '
      + 'was ein einzelner Scan maximal verbrauchen kann.',
  },
  llm: {
    title: 'LLM / AI-Provider',
    description: 'Token-Budgets und Timeouts für den AI-Provider. Das Token-Budget pro Scan verhindert '
      + 'unkontrollierte Kosten — bei 80% wird gewarnt, bei 100% wird der Scan gestoppt. '
      + 'Das monatliche Limit schützt vor Kostenexplosion.',
  },
  tool_timeouts: {
    title: 'Tool-Timeouts',
    description: 'Maximale Laufzeit pro Security-Tool in Sekunden. Wenn ein Tool länger braucht, '
      + 'wird es abgebrochen. Verhindert hängende Prozesse in der Sandbox.',
  },
  watchdog: {
    title: 'Watchdog-Überwachung',
    description: 'Der Watchdog ist ein unabhängiger Prozess der alle N Sekunden prüft ob '
      + 'die Anwendung gesund ist. Nach mehreren fehlgeschlagenen Health-Checks wird der Kill-Switch '
      + 'automatisch aktiviert. Auch die maximale Scan-Dauer wird hier überwacht.',
  },
  scan: {
    title: 'Scan-Konfiguration',
    description: 'Allgemeine Scan-Parameter: Wie viele Scans gleichzeitig laufen dürfen '
      + 'und welcher Port-Bereich standardmäßig gescannt wird wenn kein Profil gewählt ist.',
  },
  phases: {
    title: 'Scan-Phasen-Timeouts',
    description: 'Jeder Scan durchläuft mehrere Phasen (Host-Discovery, Port-Scan, Vulnerability-Scan, Report). '
      + 'Hier wird die maximale Dauer pro Phase konfiguriert.',
  },
  dsgvo: {
    title: 'DSGVO / Datenschutz',
    description: 'Datenschutz-Einstellungen gemäß DSGVO: Aufbewahrungsfristen für Scan-Daten '
      + '(ältere Scans werden automatisch gelöscht) und AVV-Warnung wenn der AI-Provider '
      + 'Daten in die USA überträgt (z.B. bei Claude/Anthropic).',
  },
  backup: {
    title: 'Backup & Wiederherstellung',
    description: 'Automatische Backups werden bei jedem Server-Start erstellt. '
      + 'Ältere Backups werden nach der konfigurierten Frist automatisch gelöscht. '
      + 'Manuelle Backups können über System → Backup ausgelöst werden.',
  },
};

interface CategoryInfoBoxProps {
  category: string;
}

/** Zeigt Beschreibung und Doku-Links für eine Einstellungskategorie */
export function CategoryInfoBox({ category }: CategoryInfoBoxProps) {
  const info = CATEGORY_INFO[category];
  if (!info) return null;

  return (
    <div className="rounded-lg border border-accent/20 bg-accent/5 px-4 py-3 mb-4">
      <p className="text-xs font-medium text-accent mb-1">{info.title}</p>
      <p className="text-[11px] text-text-secondary leading-relaxed">{info.description}</p>
      {info.links && info.links.length > 0 && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
          {info.links.map((link) => (
            <a
              key={link.url}
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-accent hover:text-accent-hover transition-colors"
            >
              <svg viewBox="0 0 16 16" fill="currentColor" className="w-3 h-3 shrink-0"><path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/><path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/></svg>
              {link.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
