import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { AlertTriangle, ChevronDown, X } from 'lucide-react';
import { useStartScan, useProfiles } from '../hooks/useApi';
import type { ScanProfile } from '../types/api';

const escalationLevels = [
  { value: 0, label: '0 — Passiv', description: 'Nur passive Aufklaerung, kein aktives Scanning' },
  { value: 1, label: '1 — Aktiv', description: 'Port-Scans und Service-Erkennung' },
  { value: 2, label: '2 — Vuln-Check', description: 'Aktive Schwachstellenpruefung' },
] as const;

export function NewScanPage() {
  const navigate = useNavigate();
  const startScan = useStartScan();
  const { data: profiles = [], isLoading: profilesLoading } = useProfiles();

  const [target, setTarget] = useState('');
  const [selectedProfile, setSelectedProfile] = useState('');
  const [customPorts, setCustomPorts] = useState('');
  const [escalation, setEscalation] = useState(2);
  const [authorized, setAuthorized] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const canSubmit = target.trim().length > 0 && authorized && !startScan.isPending;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    // Vorherigen Fehler zurücksetzen
    setScanError(null);

    startScan.mutate(
      {
        target: target.trim(),
        ...(selectedProfile ? { profile: selectedProfile } : {}),
        ...(customPorts.trim() ? { ports: customPorts.trim() } : {}),
      },
      {
        onSuccess: (data) => {
          navigate(`/scans/${data.scan_id}/live`);
        },
        onError: (error: Error) => {
          const message = error.message ?? 'Scan konnte nicht gestartet werden';
          // 503-Fehler spezifisch als "System nicht bereit" anzeigen
          if (message.includes('503')) {
            const detail = message.replace(/^API Error 503:\s*/, '');
            setScanError(`System nicht bereit: ${detail}`);
          } else {
            setScanError(message);
          }
        },
      },
    );
  }

  const activeProfile = profiles.find((p: ScanProfile) => p.name === selectedProfile);

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">Neuen Scan erstellen</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Konfigurieren und starten Sie eine Sicherheitsueberpruefung
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Ziel <span className="text-severity-critical">*</span>
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.0/24, 10.0.0.1, oder example.com"
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2.5 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 font-mono"
              autoFocus
            />
            <p className="mt-1.5 text-[11px] text-text-tertiary">
              IP-Adresse, CIDR-Bereich oder Domain
            </p>
          </div>

          {/* Scan Profile */}
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Scan-Profil
            </label>
            <div className="relative">
              <select
                value={selectedProfile}
                onChange={(e) => setSelectedProfile(e.target.value)}
                className="w-full appearance-none rounded-md border border-border-default bg-bg-primary px-3 py-2.5 pr-9 text-sm text-text-primary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
              >
                <option value="">Kein Profil (benutzerdefiniert)</option>
                {profilesLoading && <option disabled>Laden...</option>}
                {profiles.map((p: ScanProfile) => (
                  <option key={p.name} value={p.name}>
                    {p.name} — {p.description} (~{p.estimated_duration_minutes} Min.)
                  </option>
                ))}
              </select>
              <ChevronDown
                size={14}
                className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-text-tertiary"
              />
            </div>
            {activeProfile && (
              <div className="mt-2 rounded-md bg-bg-tertiary/50 px-3 py-2 text-xs text-text-secondary">
                <span className="font-medium text-text-primary">{activeProfile.name}</span>
                {' — '}
                {activeProfile.description}
                <span className="ml-2 text-text-tertiary">
                  Ports: {activeProfile.ports} | Max. Eskalation: {activeProfile.max_escalation_level} | ~{activeProfile.estimated_duration_minutes} Min.
                </span>
              </div>
            )}
          </div>

          {/* Custom Ports */}
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1.5">
              Benutzerdefinierte Ports
              <span className="ml-1 text-text-tertiary font-normal">
                {selectedProfile ? '(ueberschreibt Profil)' : '(optional)'}
              </span>
            </label>
            <input
              type="text"
              value={customPorts}
              onChange={(e) => setCustomPorts(e.target.value)}
              placeholder="z.B. 22,80,443 oder 1-1024"
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2.5 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 font-mono"
            />
          </div>
        </div>

        {/* Escalation Level */}
        <div className="rounded-lg border border-border-subtle bg-bg-secondary p-5">
          <label className="block text-xs font-medium text-text-secondary mb-3">
            Eskalationsstufe
          </label>
          <div className="space-y-2">
            {escalationLevels.map((level) => (
              <label
                key={level.value}
                className={`flex items-start gap-3 rounded-md px-3 py-2.5 cursor-pointer transition-colors ${
                  escalation === level.value
                    ? 'bg-accent/10 border border-accent/30'
                    : 'border border-transparent hover:bg-bg-tertiary/50'
                }`}
              >
                <input
                  type="radio"
                  name="escalation"
                  value={level.value}
                  checked={escalation === level.value}
                  onChange={() => setEscalation(level.value)}
                  className="mt-0.5 accent-accent"
                />
                <div>
                  <span className="text-sm font-medium text-text-primary">{level.label}</span>
                  <p className="text-xs text-text-tertiary mt-0.5">{level.description}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Legal Disclaimer */}
        <div className="rounded-lg border border-yellow-600/40 bg-yellow-950/20 p-5 space-y-3">
          <div className="flex items-start gap-3">
            <AlertTriangle size={18} className="shrink-0 text-yellow-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-yellow-400">Rechtlicher Hinweis</p>
              <p className="mt-1.5 text-xs text-yellow-200/80 leading-relaxed">
                Dieses Tool darf ausschliesslich fuer autorisierte Sicherheitsueberprufungen
                eingesetzt werden. Unautorisiertes Scannen fremder Systeme ist strafbar.
                (StGB &sect;202a-c)
              </p>
            </div>
          </div>
          <label className="flex items-center gap-2.5 cursor-pointer pt-1">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="rounded border-yellow-600/50 accent-accent h-4 w-4"
            />
            <span className="text-xs font-medium text-yellow-300">
              Ich bestaetige die Autorisierung fuer diesen Scan.
            </span>
          </label>
        </div>

        {/* Fehler-Banner */}
        {scanError && (
          <div className="rounded-md bg-severity-critical/10 border border-severity-critical/30 px-4 py-3 flex items-start justify-between gap-3">
            <p className="text-xs text-severity-critical">{scanError}</p>
            <button
              type="button"
              onClick={() => setScanError(null)}
              className="shrink-0 text-severity-critical/60 hover:text-severity-critical transition-colors"
              aria-label="Fehlermeldung schliessen"
            >
              <X size={14} />
            </button>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <Link
            to="/scans"
            className="rounded-md px-4 py-2.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
          >
            Abbrechen
          </Link>
          <button
            type="submit"
            disabled={!canSubmit}
            className="rounded-md bg-accent px-5 py-2.5 text-xs font-semibold text-white tracking-wide transition-colors hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {startScan.isPending ? 'Wird gestartet...' : 'Scan starten'}
          </button>
        </div>
      </form>
    </div>
  );
}
