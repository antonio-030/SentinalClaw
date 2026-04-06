// ── Approval-Karte für Eskalationsgenehmigungen ─────────────────────

import { useState } from 'react';
import {
  AlertTriangle, Check, X, Clock, Shield, Loader2,
} from 'lucide-react';
import { api } from '../../services/api';

interface ApprovalData {
  id: string;
  action_type: string;
  escalation_level: number;
  target: string;
  tool_name: string;
  description: string;
  risk_assessment: string;
  status: string;
  expires_at: string;
}

interface ApprovalCardProps {
  approval: ApprovalData;
  onDecided?: (id: string, status: string) => void;
}

const LEVEL_LABELS: Record<number, string> = {
  3: 'Exploitation',
  4: 'Post-Exploitation',
};

const LEVEL_COLORS: Record<number, string> = {
  3: 'border-severity-high/40 bg-severity-high/5',
  4: 'border-severity-critical/40 bg-severity-critical/5',
};

export function ApprovalCard({ approval, onDecided }: ApprovalCardProps) {
  const [loading, setLoading] = useState<'approve' | 'reject' | null>(null);

  const isExpired = new Date(approval.expires_at) < new Date();
  const isPending = approval.status === 'pending' && !isExpired;
  const levelLabel = LEVEL_LABELS[approval.escalation_level] ?? `Stufe ${approval.escalation_level}`;
  const borderColor = LEVEL_COLORS[approval.escalation_level] ?? 'border-border-subtle bg-bg-secondary';

  async function handleDecision(action: 'approve' | 'reject') {
    setLoading(action);
    try {
      const endpoint = action === 'approve'
        ? `/api/v1/approvals/${approval.id}/approve`
        : `/api/v1/approvals/${approval.id}/reject`;

      const token = localStorage.getItem('sc_token');
      await fetch(endpoint, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ reason: '' }),
      });
      onDecided?.(approval.id, action === 'approve' ? 'approved' : 'rejected');
    } catch {
      // Fehlerbehandlung über Parent
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className={`rounded-lg border-2 ${borderColor} p-4 my-3`}>
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <AlertTriangle size={16} className="text-severity-high shrink-0" />
        <span className="text-xs font-bold text-severity-high uppercase tracking-wider">
          Genehmigung erforderlich
        </span>
        <span className={`ml-auto inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
          approval.escalation_level >= 4
            ? 'bg-severity-critical/15 text-severity-critical'
            : 'bg-severity-high/15 text-severity-high'
        }`}>
          <Shield size={10} /> {levelLabel}
        </span>
      </div>

      {/* Beschreibung */}
      <p className="text-sm text-text-primary mb-3">{approval.description}</p>

      {/* Details */}
      <div className="space-y-1.5 mb-3">
        <div className="flex justify-between text-xs">
          <span className="text-text-tertiary">Ziel</span>
          <span className="text-text-primary font-mono">{approval.target}</span>
        </div>
        <div className="flex justify-between text-xs">
          <span className="text-text-tertiary">Tool</span>
          <span className="text-text-primary font-mono">{approval.tool_name}</span>
        </div>
        {approval.risk_assessment && (
          <div className="flex justify-between text-xs">
            <span className="text-text-tertiary">Risiko</span>
            <span className="text-text-primary">{approval.risk_assessment}</span>
          </div>
        )}
      </div>

      {/* Aktionen oder Status */}
      {isPending ? (
        <div className="flex gap-2">
          <button
            onClick={() => handleDecision('approve')}
            disabled={!!loading}
            className="flex-1 flex items-center justify-center gap-1.5 rounded-md bg-status-success/20 text-status-success py-2 text-xs font-semibold hover:bg-status-success/30 disabled:opacity-50 transition-colors"
          >
            {loading === 'approve' ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
            Genehmigen
          </button>
          <button
            onClick={() => handleDecision('reject')}
            disabled={!!loading}
            className="flex-1 flex items-center justify-center gap-1.5 rounded-md bg-severity-critical/20 text-severity-critical py-2 text-xs font-semibold hover:bg-severity-critical/30 disabled:opacity-50 transition-colors"
          >
            {loading === 'reject' ? <Loader2 size={13} className="animate-spin" /> : <X size={13} />}
            Ablehnen
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2 text-xs text-text-tertiary">
          <Clock size={12} />
          <span>
            {approval.status === 'approved' && 'Genehmigt'}
            {approval.status === 'rejected' && 'Abgelehnt'}
            {(approval.status === 'expired' || isExpired) && 'Abgelaufen'}
          </span>
        </div>
      )}
    </div>
  );
}
