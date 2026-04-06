import { Shield, Brain, Container, Network, Lock, Eye, Zap, FileCheck } from 'lucide-react';
import { useStatus, useHealth } from '../../hooks/useApi';

interface LayerProps {
  name: string;
  description: string;
  icon: React.ReactNode;
  active: boolean;
  color: string;
  details: string[];
  fixAction?: () => void;
  fixLabel?: string;
}

function Layer({ name, description, icon, active, color, details, fixAction, fixLabel }: LayerProps) {
  return (
    <div className={`
      relative flex items-start gap-3 rounded-lg border p-3
      ${active
        ? `border-${color}/30 bg-${color}/5`
        : 'border-severity-critical/20 bg-severity-critical/5'
      }
    `}>
      <div className="absolute left-6 top-full w-px h-2 bg-border-subtle" />

      <div className={`
        flex items-center justify-center w-8 h-8 rounded-lg shrink-0
        ${active ? `bg-${color}/10 text-${color}` : 'bg-severity-critical/10 text-severity-critical'}
      `}>
        {icon}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
          <h4 className="text-xs font-semibold text-text-primary">{name}</h4>
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
            active ? 'bg-status-success/10 text-status-success' : 'bg-severity-critical/10 text-severity-critical'
          }`}>
            {active ? '✅ AKTIV' : '❌ INAKTIV'}
          </span>
          {!active && fixAction && (
            <button
              onClick={fixAction}
              className="text-[10px] px-2 py-0.5 rounded bg-accent/10 text-accent hover:bg-accent/20 font-medium touch-manipulation"
            >
              {fixLabel || 'Starten'}
            </button>
          )}
        </div>
        <p className="text-[11px] text-text-secondary mb-1.5">{description}</p>
        <div className="flex flex-wrap gap-1">
          {details.map((detail, i) => (
            <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-bg-primary border border-border-subtle text-text-tertiary">
              {detail}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

export function SecurityLayers() {
  const { data: status } = useStatus();
  const { data: health } = useHealth();

  const sys = status?.system;
  const online = health?.status === 'ok';

  const layers: LayerProps[] = [
    {
      name: 'NVIDIA NemoClaw Runtime',
      description: 'Agent-Orchestrierung und OpenShell-Sandbox',
      icon: <Brain size={16} />,
      active: !!sys?.nemoclaw_available,
      color: 'accent',
      details: ['OpenClaw Agent', 'Landlock + seccomp', 'OpenShell Sandbox'],
    },
    {
      name: 'Scope-Validator',
      description: '7 Sicherheits-Checks vor jedem Tool-Aufruf',
      icon: <Shield size={16} />,
      active: online,
      color: 'accent',
      details: ['Target-Whitelist', 'Port-Range', 'Eskalation', 'Zeitfenster', 'Tool-Allowlist', 'Forbidden-IPs', 'Exclude-List'],
    },
    {
      name: 'Input-Validierung',
      description: 'Command-Injection-Prevention, PII-Sanitizer',
      icon: <FileCheck size={16} />,
      active: online,
      color: 'accent',
      details: ['Shell-Metazeichen', 'Binary-Allowlist', 'nmap-Flag-Filter', 'PII-Masking'],
    },
    {
      name: 'Docker Sandbox',
      description: 'Isolierte Tool-Ausführung im Container',
      icon: <Container size={16} />,
      active: !!sys?.sandbox_running,
      color: 'status-success',
      details: ['cap_drop ALL', 'NET_RAW', 'read-only FS', 'non-root', 'PID-Limit 256'],
      fixAction: !sys?.sandbox_running ? async () => {
        await fetch('/api/v1/sandbox/start', { method: 'POST', headers: { 'Authorization': `Bearer ${localStorage.getItem('sc_token')}` } });
        setTimeout(() => window.location.reload(), 2000);
      } : undefined,
      fixLabel: 'Sandbox starten',
    },
    {
      name: 'Netzwerk-Isolation',
      description: 'Nur Whitelist-Ziele erreichbar',
      icon: <Network size={16} />,
      active: !!sys?.sandbox_running,
      color: 'status-success',
      details: ['sentinel-internal', 'sentinel-scanning', 'Kein Internet'],
    },
    {
      name: 'Kill Switch',
      description: '4 unabhängige Kill-Pfade, Watchdog-Überwachung',
      icon: <Zap size={16} />,
      active: !sys?.kill_switch_active,
      color: 'severity-critical',
      details: ['App-Kill', 'Container-Kill', 'Netzwerk-Kill', 'OS-Kill', 'Watchdog'],
    },
    {
      name: 'Audit-Logging',
      description: 'Unveränderliches Protokoll aller Aktionen',
      icon: <Eye size={16} />,
      active: !!health?.db_connected,
      color: 'accent',
      details: ['Append-Only', 'Kein DELETE', 'Zeitstempel', 'User-ID'],
    },
    {
      name: 'Authentifizierung & RBAC',
      description: 'JWT-Token, 5 Rollen, Passwort-Hashing',
      icon: <Lock size={16} />,
      active: online,
      color: 'accent',
      details: ['JWT (HS256)', 'bcrypt', '5 Rollen', 'Login', 'Token-Expiry'],
    },
  ];

  const activeCount = layers.filter(l => l.active).length;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-text-primary">Sicherheitsschichten</h2>
        <span className="text-[11px] font-medium text-status-success">
          {activeCount}/{layers.length} aktiv
        </span>
      </div>
      <div className="space-y-2">
        {layers.map((layer, i) => (
          <Layer key={i} {...layer} />
        ))}
      </div>
    </div>
  );
}
