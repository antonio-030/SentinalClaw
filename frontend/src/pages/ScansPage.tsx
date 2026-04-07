import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, X, Radar, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import { useScans } from '../hooks/useApi';
import { showToast } from '../components/shared/NotificationToast';
import { StatusBadge } from '../components/shared/StatusBadge';
import { formatDateShort } from '../utils/format';
import type { Scan } from '../types/api';

export function ScansPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [target, setTarget] = useState('');
  const [ports, setPorts] = useState('');
  const [profile, setProfile] = useState('');

  const { data: scans = [], isLoading, isError, error, refetch } = useScans();

  const createMutation = useMutation({
    mutationFn: api.scans.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['status'] });
      setShowModal(false);
      setTarget('');
      setPorts('');
      setProfile('');
      showToast('success', 'Scan gestartet', `Ziel: ${target.trim()}`);
    },
    onError: (err: Error) => {
      showToast('error', 'Scan konnte nicht gestartet werden', err.message);
    },
  });

  const sorted = useMemo(() =>
    [...scans].sort(
      (a: Scan, b: Scan) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    ),
    [scans]
  );

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) return;
    createMutation.mutate({
      target: target.trim(),
      ...(ports.trim() ? { ports: ports.trim() } : {}),
      ...(profile.trim() ? { profile: profile.trim() } : {}),
    });
  }

  if (isLoading) return <div className="flex justify-center py-16"><div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" /></div>;

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-severity-critical/10 mb-4">
          <AlertCircle className="h-6 w-6 text-severity-critical" />
        </div>
        <h2 className="text-sm font-semibold text-text-primary mb-1">Fehler beim Laden</h2>
        <p className="text-xs text-text-tertiary max-w-sm mb-4">
          {(error as Error | null)?.message || 'Unbekannter Fehler'}
        </p>
        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-1.5 rounded-md bg-accent/10 border border-accent/30 px-3.5 py-2 text-xs font-medium text-accent hover:bg-accent/20 transition-colors"
        >
          Erneut versuchen
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary tracking-tight">Scans</h1>
          <p className="mt-1 text-sm text-text-secondary">Manage and monitor scan jobs</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 rounded-md bg-accent px-3.5 py-2 text-xs font-semibold text-white tracking-wide transition-colors hover:bg-accent-hover"
        >
          <Plus size={14} strokeWidth={2.5} />
          New Scan
        </button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border-subtle bg-bg-secondary overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left">
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Status</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Target</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Type</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Tokens</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Started</th>
                <th className="px-5 py-3 text-xs font-medium text-text-tertiary uppercase tracking-wider">Completed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center">
                    <Radar size={28} className="mx-auto mb-3 text-text-tertiary" strokeWidth={1.5} />
                    <p className="text-sm text-text-tertiary">No scans found</p>
                    <p className="text-xs text-text-tertiary mt-1">Create a new scan to get started</p>
                  </td>
                </tr>
              )}
              {sorted.map((scan: Scan) => (
                <tr key={scan.id} className="hover:bg-bg-tertiary/30 transition-colors cursor-pointer" onClick={() => navigate(`/scans/${scan.id}`)} tabIndex={0} role="link" onKeyDown={(e) => { if (e.key === 'Enter') navigate(`/scans/${scan.id}`); }}>
                  <td className="px-5 py-3.5">
                    <StatusBadge status={scan.status} compact />
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-text-primary">{scan.target}</td>
                  <td className="px-5 py-3.5 text-xs text-text-secondary">{scan.scan_type}</td>
                  <td className="px-5 py-3.5 text-xs text-text-secondary tabular-nums">
                    {scan.tokens_used.toLocaleString()}
                  </td>
                  <td className="px-5 py-3.5 text-xs text-text-tertiary tabular-nums">{formatDateShort(scan.started_at)}</td>
                  <td className="px-5 py-3.5 text-xs text-text-tertiary tabular-nums">{formatDateShort(scan.completed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* New Scan Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setShowModal(false)}
          />
          {/* Modal */}
          <div className="relative w-full max-w-md rounded-xl border border-border-default bg-bg-secondary shadow-2xl">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle">
              <h2 className="text-sm font-semibold text-text-primary">New Scan</h2>
              <button
                onClick={() => setShowModal(false)}
                aria-label="Dialog schließen"
                className="rounded-md p-1 text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreate} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Target *</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.0/24 or example.com"
                  className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 font-mono"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Ports</label>
                <input
                  type="text"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="1-1000 (default)"
                  className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Profile</label>
                <input
                  type="text"
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  placeholder="quick, standard, thorough"
                  className="w-full rounded-md border border-border-default bg-bg-primary px-3 py-2 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
                />
              </div>
              {createMutation.isError && (
                <p className="text-xs text-severity-critical">
                  {(createMutation.error as Error).message ?? 'Failed to create scan'}
                </p>
              )}
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-md px-3.5 py-2 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!target.trim() || createMutation.isPending}
                  className="rounded-md bg-accent px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {createMutation.isPending ? 'Starting...' : 'Start Scan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
