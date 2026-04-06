import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useProfiles, useCreateProfile, useDeleteProfile } from '../hooks/useApi';
import {
  Layers, Clock, Zap, Globe, Loader2, Plus, Trash2, Shield, X,
} from 'lucide-react';
import type { ScanProfile } from '../types/api';

const ESCALATION_LABELS: Record<number, string> = {
  0: 'Passiv', 1: 'Aktiv', 2: 'Vuln-Check', 3: 'Exploit', 4: 'Post-Exploit',
};
const ESCALATION_COLORS: Record<number, string> = {
  0: 'bg-status-success/15 text-status-success',
  1: 'bg-accent/15 text-accent',
  2: 'bg-severity-medium/15 text-severity-medium',
  3: 'bg-severity-high/15 text-severity-high',
  4: 'bg-severity-critical/15 text-severity-critical',
};

function EscalationBadge({ level }: { level: number }) {
  const label = ESCALATION_LABELS[level] ?? `Stufe ${level}`;
  const color = ESCALATION_COLORS[level] ?? 'bg-bg-tertiary text-text-secondary';
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${color}`}>
      <Zap size={11} /> {label} (Stufe {level})
    </span>
  );
}

// ── Profil-Karte mit Delete-Option ──────────────────────────────────

function ProfileCard({ profile, onDelete }: {
  profile: ScanProfile; onDelete: (id: string) => void;
}) {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col rounded-lg border border-border-subtle bg-bg-secondary p-5">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <Layers size={18} strokeWidth={1.8} className="text-accent shrink-0 mt-0.5" />
          <h2 className="text-base font-semibold text-text-primary leading-tight">
            {profile.name}
          </h2>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {profile.is_builtin ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-accent/10 text-accent px-2 py-0.5 text-[10px] font-medium">
              <Shield size={10} /> Vordefiniert
            </span>
          ) : (
            <button
              onClick={() => onDelete(profile.id)}
              className="rounded-md p-1 text-text-tertiary hover:text-severity-critical hover:bg-severity-critical/10 transition-colors"
              title="Profil löschen"
            >
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>

      <p className="text-sm text-text-secondary leading-relaxed mb-4">{profile.description}</p>

      <div className="space-y-2.5 mb-5 flex-1">
        <div className="flex items-center justify-between gap-4">
          <span className="text-xs text-text-tertiary">Ports</span>
          <span className="text-xs text-text-primary font-mono text-right truncate max-w-[180px]">
            {profile.ports || '--'}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span className="text-xs text-text-tertiary">Eskalationsstufe</span>
          <EscalationBadge level={profile.max_escalation_level} />
        </div>
        <div className="flex items-center justify-between gap-4">
          <span className="text-xs text-text-tertiary">Geschätzte Dauer</span>
          <span className="inline-flex items-center gap-1.5 text-xs text-text-primary">
            <Clock size={12} className="text-text-tertiary" /> ~{profile.estimated_duration_minutes} Min.
          </span>
        </div>
      </div>

      <button
        onClick={() => navigate(`/scans/new?profile=${encodeURIComponent(profile.name)}`)}
        className="w-full rounded-md bg-accent/15 text-accent text-sm font-medium py-2.5 hover:bg-accent/25 transition-colors"
      >
        Scan mit diesem Profil
      </button>
    </div>
  );
}

// ── Profil-Erstellungs-Modal ────────────────────────────────────────

function ProfileFormModal({ onClose }: { onClose: () => void }) {
  const createMutation = useCreateProfile();
  const [form, setForm] = useState({
    name: '', description: '', ports: '1-1000',
    max_escalation_level: 2, skip_host_discovery: false,
    skip_vuln_scan: false, nmap_extra_flags: [] as string[],
    estimated_duration_minutes: 5,
  });

  function set<K extends keyof typeof form>(key: K, val: (typeof form)[K]) {
    setForm((prev) => ({ ...prev, [key]: val }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    await createMutation.mutateAsync(form);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-lg border border-border-subtle bg-bg-secondary p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-text-primary">Neues Scan-Profil</h2>
          <button onClick={onClose} className="text-text-tertiary hover:text-text-primary">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">Name *</label>
            <input required value={form.name} onChange={(e) => set('name', e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent" />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">Beschreibung</label>
            <input value={form.description} onChange={(e) => set('description', e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent" />
          </div>
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">Ports *</label>
            <input required value={form.ports} onChange={(e) => set('ports', e.target.value)} placeholder="z.B. 1-1000 oder 80,443,8080"
              className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary font-mono focus:outline-none focus:ring-1 focus:ring-accent" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Eskalationsstufe</label>
              <select value={form.max_escalation_level}
                onChange={(e) => set('max_escalation_level', Number(e.target.value))}
                className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent">
                {[0,1,2,3,4].map((l) => (
                  <option key={l} value={l}>{ESCALATION_LABELS[l]} ({l})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Geschätzte Dauer (Min.)</label>
              <input type="number" min={1} max={120} value={form.estimated_duration_minutes}
                onChange={(e) => set('estimated_duration_minutes', Number(e.target.value))}
                className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent" />
            </div>
          </div>

          <div className="flex gap-6">
            <label className="inline-flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
              <input type="checkbox" checked={form.skip_host_discovery}
                onChange={(e) => set('skip_host_discovery', e.target.checked)}
                className="rounded border-border-default" />
              Host-Discovery überspringen
            </label>
            <label className="inline-flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
              <input type="checkbox" checked={form.skip_vuln_scan}
                onChange={(e) => set('skip_vuln_scan', e.target.checked)}
                className="rounded border-border-default" />
              Vuln-Scan überspringen
            </label>
          </div>

          {createMutation.isError && (
            <p className="text-xs text-severity-critical">
              Fehler: {createMutation.error?.message}
            </p>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="rounded-md px-4 py-2 text-xs text-text-secondary hover:text-text-primary transition-colors">
              Abbrechen
            </button>
            <button type="submit" disabled={createMutation.isPending}
              className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50 transition-colors">
              {createMutation.isPending && <Loader2 size={12} className="animate-spin" />}
              Profil erstellen
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Hauptseite ──────────────────────────────────────────────────────

export function ProfilesPage() {
  const { data: profiles, isLoading, isError, error } = useProfiles();
  const deleteMutation = useDeleteProfile();
  const [showCreate, setShowCreate] = useState(false);

  function handleDelete(id: string) {
    if (confirm('Profil wirklich löschen?')) deleteMutation.mutate(id);
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin text-text-tertiary" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="rounded-lg border border-severity-high/20 bg-severity-high/5 px-5 py-4">
          <p className="text-sm text-severity-high">
            Fehler: {(error as Error)?.message ?? 'Unbekannter Fehler'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <Globe size={22} strokeWidth={1.8} className="text-text-tertiary mt-0.5 shrink-0" />
          <div>
            <h1 className="text-xl font-semibold text-text-primary tracking-tight">Scan-Profile</h1>
            <p className="mt-1 text-sm text-text-secondary">
              Vordefinierte und eigene Konfigurationen für Scan-Szenarien.
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-medium text-white hover:bg-accent/90 transition-colors shrink-0"
        >
          <Plus size={14} /> Neues Profil
        </button>
      </div>

      {profiles && profiles.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {profiles.map((profile) => (
            <ProfileCard key={profile.id ?? profile.name} profile={profile} onDelete={handleDelete} />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-border-subtle bg-bg-secondary px-5 py-10 text-center">
          <Layers size={32} className="mx-auto text-text-tertiary mb-3" />
          <p className="text-sm text-text-secondary">Keine Scan-Profile verfügbar.</p>
        </div>
      )}

      {showCreate && <ProfileFormModal onClose={() => setShowCreate(false)} />}
    </div>
  );
}
