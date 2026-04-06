// ── Whitelist — Autorisierte Scan-Ziele verwalten ────────────────────

import { useState } from 'react';
import { ShieldCheck, Plus, Trash2, AlertTriangle, Network } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useWhitelist, useAuthorizeTarget, useRevokeTarget } from '../hooks/useApi';
import { showToast } from '../components/shared/NotificationToast';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { api } from '../services/api';

export function WhitelistPage() {
  const { data: targets, isLoading } = useWhitelist();
  const { data: policy } = useQuery({
    queryKey: ['policy'],
    queryFn: api.whitelist.policy,
    staleTime: 30_000,
  });
  const authorizeMut = useAuthorizeTarget();
  const revokeMut = useRevokeTarget();

  const [target, setTarget] = useState('');
  const [notes, setNotes] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [confirmation, setConfirmation] = useState('owner');

  async function handleAuthorize(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim() || !confirmed) return;

    try {
      await authorizeMut.mutateAsync({ target: target.trim(), confirmation, notes });
      showToast('success', 'Ziel autorisiert', target.trim());
      setTarget('');
      setNotes('');
      setConfirmed(false);
    } catch (err) {
      showToast('error', 'Autorisierung fehlgeschlagen',
        err instanceof Error ? err.message : 'Unbekannter Fehler');
    }
  }

  async function handleRevoke(id: string, name: string) {
    try {
      await revokeMut.mutateAsync(id);
      showToast('success', 'Autorisierung widerrufen', name);
    } catch (err) {
      showToast('error', 'Fehler', err instanceof Error ? err.message : 'Unbekannter Fehler');
    }
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-text-primary tracking-tight">
          Scan-Whitelist
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Nur autorisierte Ziele dürfen mit aktiven Tools gescannt werden
        </p>
      </div>

      {/* Ziel hinzufügen */}
      <form onSubmit={handleAuthorize}
        className="rounded-lg border border-border-subtle bg-bg-secondary p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text-primary">Ziel autorisieren</h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-text-secondary mb-1.5">
              Ziel (Domain, IP oder CIDR)
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="z.B. example.com oder 10.0.0.0/24"
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2.5 text-sm text-text-primary font-mono placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
            />
          </div>
          <div>
            <label className="block text-xs text-text-secondary mb-1.5">Art der Berechtigung</label>
            <select
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              className="w-full appearance-none rounded-md border border-border-default bg-bg-primary px-3 py-2.5 text-sm text-text-primary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
            >
              <option value="owner">Ich bin Eigentümer</option>
              <option value="pentest_mandate">Schriftlicher Pentest-Auftrag</option>
              <option value="internal">Internes System</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs text-text-secondary mb-1.5">Notizen (optional)</label>
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="z.B. Auftragsnummer, Ansprechpartner..."
            className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2.5 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
          />
        </div>

        {/* Bestätigungs-Checkbox */}
        <label className="flex items-start gap-3 rounded-md border border-severity-critical/20 bg-severity-critical/5 p-4 cursor-pointer">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-border-default accent-accent"
          />
          <div>
            <p className="text-sm font-medium text-text-primary">
              Ich bestätige die Autorisierung
            </p>
            <p className="text-xs text-text-secondary mt-0.5">
              Ich bin berechtigt, dieses Ziel aktiv zu scannen (inkl. SQL-Injection,
              Port-Scans, Vulnerability-Checks). Unberechtigtes Scannen ist strafbar
              (§202a, §303b StGB).
            </p>
          </div>
        </label>

        <button
          type="submit"
          disabled={!target.trim() || !confirmed || authorizeMut.isPending}
          className="inline-flex items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-medium text-white hover:bg-accent/85 active:scale-95 transition-all disabled:opacity-40"
        >
          {authorizeMut.isPending ? <LoadingSpinner size="sm" /> : <Plus size={15} />}
          Ziel autorisieren
        </button>
      </form>

      {/* Autorisierte Ziele */}
      <section className="rounded-lg border border-border-subtle bg-bg-secondary">
        <div className="flex items-center gap-2.5 px-5 py-4 border-b border-border-subtle">
          <ShieldCheck size={16} strokeWidth={1.8} className="text-text-tertiary" />
          <h2 className="text-sm font-semibold text-text-primary">
            Autorisierte Ziele ({targets?.length ?? 0})
          </h2>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-8"><LoadingSpinner size="md" /></div>
        ) : !targets?.length ? (
          <div className="text-center py-8">
            <AlertTriangle size={24} className="mx-auto text-text-tertiary mb-2" />
            <p className="text-sm text-text-secondary">Keine Ziele autorisiert</p>
            <p className="text-xs text-text-tertiary mt-1">
              Füge oben ein Ziel hinzu um aktive Scans zu ermöglichen
            </p>
          </div>
        ) : (
          <div className="divide-y divide-border-subtle">
            {targets.map((t) => (
              <div key={t.id} className="flex items-center gap-4 px-5 py-3.5 hover:bg-bg-tertiary/30 transition-colors">
                <ShieldCheck size={15} className="text-status-success shrink-0" />
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-mono text-text-primary">{t.target}</span>
                  <span className="ml-2 text-[10px] text-text-tertiary uppercase">
                    {t.confirmation === 'owner' ? 'Eigentümer' :
                     t.confirmation === 'pentest_mandate' ? 'Pentest-Auftrag' : 'Intern'}
                  </span>
                  {t.notes && <p className="text-xs text-text-tertiary truncate">{t.notes}</p>}
                </div>
                <button
                  onClick={() => handleRevoke(t.id, t.target)}
                  disabled={revokeMut.isPending}
                  className="shrink-0 p-1.5 rounded text-text-tertiary hover:text-status-error transition-colors"
                  aria-label="Autorisierung widerrufen"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Netzwerk-Policy Status */}
      <section className="rounded-lg border border-border-subtle bg-bg-secondary">
        <div className="flex items-center gap-2.5 px-5 py-4 border-b border-border-subtle">
          <Network size={16} strokeWidth={1.8} className="text-text-tertiary" />
          <h2 className="text-sm font-semibold text-text-primary">Netzwerk-Policy</h2>
        </div>
        <div className="px-5 py-4 space-y-2">
          <div className="flex items-center justify-between py-1.5">
            <span className="text-xs text-text-secondary">Status</span>
            <span className="text-xs font-mono text-text-primary">
              {policy?.status ?? '—'}
            </span>
          </div>
          <div className="flex items-center justify-between py-1.5">
            <span className="text-xs text-text-secondary">Version</span>
            <span className="text-xs font-mono text-text-primary">
              {policy?.version ?? '—'}
            </span>
          </div>
          <div className="flex items-center justify-between py-1.5">
            <span className="text-xs text-text-secondary">Hash</span>
            <span className="text-xs font-mono text-text-tertiary truncate max-w-[200px]">
              {policy?.hash ?? '—'}
            </span>
          </div>
          <p className="text-[10px] text-text-tertiary pt-2">
            Die Netzwerk-Policy wird automatisch aktualisiert wenn Ziele
            autorisiert oder widerrufen werden.
          </p>
        </div>
      </section>
    </div>
  );
}
