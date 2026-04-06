// ── Animierte Sicherheitsschicht-Visualisierung ─────────────────────

import { useState, useMemo } from 'react';
import { Shield, Brain, FileCheck, Container, Network, Zap, Eye, Lock } from 'lucide-react';
import { useStatus, useHealth } from '../../hooks/useApi';
import { LayerDetailPanel } from './LayerDetailPanel';
import type { LayerData } from './LayerDetailPanel';

// Schichtfarben — nicht über Tailwind, direkt als Hex (SVG inline styles)
const LAYER_COLORS = [
  '#3B82F6', // NemoClaw — Blau
  '#22C55E', // Scope — Grün
  '#EAB308', // Input — Gelb
  '#3B82F6', // Docker — Blau
  '#8B5CF6', // Netzwerk — Violett
  '#EF4444', // Kill — Rot
  '#6B7280', // Audit — Grau
  '#22C55E', // Auth — Grün
] as const;

const CENTER = 300;
const RING_GAP = 28;
const INNER_RADIUS = 55;

function ringRadius(index: number): number {
  return INNER_RADIUS + (index + 1) * RING_GAP;
}

export function SecurityShield() {
  const { data: status } = useStatus();
  const { data: health } = useHealth();
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  const sys = status?.system;
  const online = health?.status === 'ok';

  const layers: LayerData[] = useMemo(() => [
    { name: 'NemoClaw Runtime', description: 'Agent-Orchestrierung und OpenShell-Sandbox mit Kernel-Isolation.',
      icon: <Brain size={16} />, active: !!sys?.nemoclaw_available, color: LAYER_COLORS[0],
      details: ['OpenClaw Agent', 'Landlock + seccomp', 'OpenShell Sandbox'] },
    { name: 'Scope-Validator', description: '7 unabhängige Sicherheits-Checks vor jedem Tool-Aufruf.',
      icon: <Shield size={16} />, active: online, color: LAYER_COLORS[1],
      details: ['Target-Whitelist', 'Port-Range', 'Eskalation', 'Zeitfenster', 'Tool-Allowlist', 'Forbidden-IPs', 'Exclude-List'] },
    { name: 'Input-Validierung', description: 'Command-Injection-Prevention und PII-Sanitizer.',
      icon: <FileCheck size={16} />, active: online, color: LAYER_COLORS[2],
      details: ['Shell-Metazeichen', 'Binary-Allowlist', 'nmap-Flag-Filter', 'PII-Masking'] },
    { name: 'Docker Sandbox', description: 'Gehärteter Container mit minimalen Capabilities.',
      icon: <Container size={16} />, active: !!sys?.sandbox_running, color: LAYER_COLORS[3],
      details: ['cap_drop ALL', 'NET_RAW only', 'read-only FS', 'non-root User', 'PID-Limit 256'] },
    { name: 'Netzwerk-Isolation', description: 'Segmentierte Netzwerke — nur Whitelist-Ziele erreichbar.',
      icon: <Network size={16} />, active: !!sys?.sandbox_running, color: LAYER_COLORS[4],
      details: ['sentinel-internal', 'sentinel-scanning', 'Kein Internet-Zugang'] },
    { name: 'Kill Switch', description: '4 unabhängige Kill-Pfade mit Watchdog-Überwachung.',
      icon: <Zap size={16} />, active: !sys?.kill_switch_active, color: LAYER_COLORS[5],
      details: ['App-Kill (<1s)', 'Container-Kill (<3s)', 'Netzwerk-Kill (<1s)', 'OS-Kill (<5s)', 'Watchdog'] },
    { name: 'Audit-Logging', description: 'Unveränderliches, append-only Protokoll aller Aktionen.',
      icon: <Eye size={16} />, active: !!health?.db_connected, color: LAYER_COLORS[6],
      details: ['Append-Only', 'Kein DELETE', 'Zeitstempel', 'User-ID'] },
    { name: 'Auth & RBAC', description: 'JWT-basierte Authentifizierung mit 5-Stufen-Rollenmodell.',
      icon: <Lock size={16} />, active: online, color: LAYER_COLORS[7],
      details: ['JWT (HS256)', 'bcrypt Hashing', '5 RBAC-Rollen', 'MFA (TOTP)', 'Token-Expiry'] },
  ], [sys, online, health]);

  const activeCount = layers.filter((l) => l.active).length;
  const selected = selectedIndex !== null ? layers[selectedIndex] : null;

  return (
    <div>
      {/* Überschrift */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-text-primary tracking-wide">Sicherheitsschichten</h2>
        <span className="text-xs font-mono font-semibold" style={{ color: activeCount === 8 ? '#22C55E' : '#EAB308' }}>
          {activeCount}/{layers.length} aktiv
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_300px] gap-5 items-start">
        {/* SVG Shield */}
        <div className="relative w-full max-w-[540px] mx-auto aspect-square">
          <svg viewBox="0 0 600 600" className="w-full h-full" style={{ filter: 'drop-shadow(0 0 40px rgba(59,130,246,0.08))' }}>
            <defs>
              {/* Glow-Filter für aktive Ringe */}
              {LAYER_COLORS.map((color, i) => (
                <filter key={i} id={`glow-${i}`} x="-50%" y="-50%" width="200%" height="200%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feFlood floodColor={color} floodOpacity="0.4" result="color" />
                  <feComposite in="color" in2="blur" operator="in" result="shadow" />
                  <feMerge>
                    <feMergeNode in="shadow" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              ))}
            </defs>

            {/* Ringe von außen nach innen (damit innere ÜBER äußeren liegen) */}
            {[...layers].reverse().map((layer, reverseI) => {
              const i = layers.length - 1 - reverseI;
              const r = ringRadius(i);
              const isActive = layer.active;
              const isSelected = selectedIndex === i;
              const color = LAYER_COLORS[i];
              // Abwechselnde Rotation: gerade = CW, ungerade = CCW
              const duration = 100 + i * 20;
              const direction = i % 2 === 0 ? 'normal' : 'reverse';

              return (
                <g key={i} style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}>
                  {/* Hauptring */}
                  <circle
                    cx={CENTER} cy={CENTER} r={r}
                    fill="none"
                    stroke={color}
                    strokeWidth={isSelected ? 5 : 3}
                    strokeOpacity={isActive ? 0.8 : 0.15}
                    strokeDasharray={isActive ? 'none' : '6 4'}
                    filter={isActive ? `url(#glow-${i})` : undefined}
                    style={{
                      animation: isActive
                        ? `ring-pulse 3s ease-in-out ${i * 0.3}s infinite, ring-rotate ${duration}s linear infinite ${direction}`
                        : undefined,
                      transformOrigin: `${CENTER}px ${CENTER}px`,
                    }}
                  />

                  {/* Klickbarer, unsichtbarer Ring (breiterer Hitbereich) */}
                  <circle
                    cx={CENTER} cy={CENTER} r={r}
                    fill="none" stroke="transparent" strokeWidth={18}
                    className="cursor-pointer"
                    onClick={() => setSelectedIndex(selectedIndex === i ? null : i)}
                  />

                  {/* Orbiting Partikel (nur für aktive Ringe, jeden zweiten) */}
                  {isActive && i % 2 === 0 && (
                    <>
                      <circle r="2.5" fill={color} opacity="0.9" style={{ filter: `drop-shadow(0 0 3px ${color})` }}>
                        <animateMotion dur={`${6 + i * 2}s`} repeatCount="indefinite">
                          <mpath xlinkHref={`#orbit-${i}`} />
                        </animateMotion>
                      </circle>
                      <circle id={`orbit-helper-${i}`} cx={CENTER} cy={CENTER} r={r} fill="none" stroke="none" />
                      {/* Unsichtbarer Pfad für die Partikel-Orbit-Animation */}
                    </>
                  )}
                </g>
              );
            })}

            {/* Orbit-Pfade (unsichtbar, für animateMotion) */}
            {layers.map((_, i) => (
              <circle key={`orbit-${i}`} id={`orbit-${i}`} cx={CENTER} cy={CENTER} r={ringRadius(i)} fill="none" stroke="none" />
            ))}

            {/* Zweite Partikel-Gruppe (versetzt) */}
            {layers.map((layer, i) => (
              layer.active && i % 2 === 1 ? (
                <circle key={`p2-${i}`} r="2" fill={LAYER_COLORS[i]} opacity="0.7"
                  style={{ filter: `drop-shadow(0 0 2px ${LAYER_COLORS[i]})` }}>
                  <animateMotion dur={`${8 + i * 1.5}s`} begin={`${i * 0.5}s`} repeatCount="indefinite">
                    <mpath xlinkHref={`#orbit-${i}`} />
                  </animateMotion>
                </circle>
              ) : null
            ))}

            {/* Ring-Labels (an festen Positionen um den Kreis) */}
            {layers.map((layer, i) => {
              const r = ringRadius(i) + 2;
              // Jeder Label an einer anderen Winkelposition verteilt
              const angle = -90 + i * 42;
              const rad = (angle * Math.PI) / 180;
              const lx = CENTER + r * Math.cos(rad);
              const ly = CENTER + r * Math.sin(rad);
              const isRight = lx > CENTER;

              return (
                <g key={`label-${i}`} opacity={layer.active ? 0.9 : 0.3}>
                  {/* Verbindungslinie vom Ring zum Label */}
                  <line x1={lx} y1={ly}
                    x2={lx + (isRight ? 14 : -14)} y2={ly}
                    stroke={LAYER_COLORS[i]} strokeWidth="0.8" strokeOpacity="0.5" />
                  <circle cx={lx} cy={ly} r="2" fill={LAYER_COLORS[i]} />
                  <text
                    x={lx + (isRight ? 18 : -18)} y={ly + 3.5}
                    textAnchor={isRight ? 'start' : 'end'}
                    fill="#8B95A8" fontSize="9" fontFamily="Geist, sans-serif"
                    fontWeight={selectedIndex === i ? 700 : 400}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedIndex(selectedIndex === i ? null : i)}
                  >
                    {layer.name}
                  </text>
                </g>
              );
            })}

            {/* Zentrum — Logo + Status */}
            <circle cx={CENTER} cy={CENTER} r={INNER_RADIUS - 6} fill="#0C0E12" stroke="#1E2330" strokeWidth="1" />
            <circle cx={CENTER} cy={CENTER} r={INNER_RADIUS - 16} fill="none" stroke="#3B82F6" strokeWidth="0.5" strokeOpacity="0.3" strokeDasharray="2 3" />
            {/* Shield-Icon im Zentrum */}
            <g transform={`translate(${CENTER - 10}, ${CENTER - 18})`} opacity="0.7">
              <path d="M10 1L19 5V11C19 16.5 15 21 10 23C5 21 1 16.5 1 11V5L10 1Z" stroke="#3B82F6" strokeWidth="1.2" fill="none" />
            </g>
            <text x={CENTER} y={CENTER + 18} textAnchor="middle" fill="#5A6478" fontSize="7" fontFamily="Geist Mono, monospace" letterSpacing="2">
              SENTINELCLAW
            </text>
          </svg>

          {/* Auswahl-Indikator-Highlight um das Gesamtbild */}
          {selectedIndex !== null && (
            <div
              className="absolute inset-0 rounded-full pointer-events-none"
              style={{
                boxShadow: `inset 0 0 60px ${LAYER_COLORS[selectedIndex]}08, 0 0 80px ${LAYER_COLORS[selectedIndex]}05`,
              }}
            />
          )}
        </div>

        {/* Detail Panel */}
        <LayerDetailPanel layer={selected} />
      </div>
    </div>
  );
}
