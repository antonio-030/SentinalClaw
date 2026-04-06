import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Radar, AlertTriangle, ScrollText, FileText, Download, GitCompare, Activity, Settings, X, Layers, ShieldCheck, Package, Brain } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const navItems: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/scans', label: 'Scans', icon: Radar },
  { to: '/findings', label: 'Findings', icon: AlertTriangle },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/export', label: 'Export', icon: Download },
  { to: '/compare', label: 'Compare', icon: GitCompare },
  { to: '/monitoring', label: 'Monitoring', icon: Activity },
];

interface SidebarProps {
  runningScans?: number;
  onNavigate?: () => void;
}

export function Sidebar({ runningScans = 0, onNavigate }: SidebarProps) {
  return (
    <aside className="h-full w-full flex flex-col bg-bg-secondary border-r border-border-subtle">
      {/* Mobile: Schließen-Button */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle lg:hidden">
        <span className="text-sm font-semibold text-text-primary">Navigation</span>
        <button
          onClick={onNavigate}
          aria-label="Navigation schließen"
          className="p-1 rounded text-text-secondary hover:text-text-primary hover:bg-bg-tertiary"
        >
          <X size={18} />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        <p className="hidden lg:block px-3 mb-3 text-[10px] font-semibold tracking-widest uppercase text-text-tertiary">
          Navigation
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            onClick={onNavigate}
            className={({ isActive }) =>
              `group flex items-center gap-3 rounded-md px-3 py-2.5 lg:py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-bg-tertiary text-text-primary border-l-2 border-accent pl-[10px]'
                  : 'text-text-secondary hover:bg-bg-tertiary/50 hover:text-text-primary border-l-2 border-transparent pl-[10px]'
              }`
            }
          >
            <item.icon size={17} strokeWidth={1.8} className="shrink-0" />
            <span className="flex-1">{item.label}</span>
            {item.label === 'Scans' && runningScans > 0 && (
              <span className="flex items-center justify-center min-w-[20px] h-5 rounded-full bg-accent/15 text-accent text-[11px] font-semibold px-1.5">
                {runningScans}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Konfiguration */}
      <div className="px-3 pb-1">
        <p className="px-3 mb-2 text-[10px] font-semibold tracking-widest uppercase text-text-tertiary">
          Konfiguration
        </p>
        {([
          { to: '/profiles', label: 'Profile', icon: Layers },
          { to: '/whitelist', label: 'Whitelist', icon: ShieldCheck },
          { to: '/agent-tools', label: 'Agent Tools', icon: Package },
          { to: '/workspace', label: 'Workspace', icon: Brain },
        ] as NavItem[]).map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              `group flex items-center gap-3 rounded-md px-3 py-2.5 lg:py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-bg-tertiary text-text-primary border-l-2 border-accent pl-[10px]'
                  : 'text-text-secondary hover:bg-bg-tertiary/50 hover:text-text-primary border-l-2 border-transparent pl-[10px]'
              }`
            }
          >
            <item.icon size={17} strokeWidth={1.8} className="shrink-0" />
            <span className="flex-1">{item.label}</span>
          </NavLink>
        ))}
      </div>

      {/* Settings */}
      <div className="px-3 pb-2">
        <NavLink
          to="/settings"
          onClick={onNavigate}
          className={({ isActive }) =>
            `group flex items-center gap-3 rounded-md px-3 py-2.5 lg:py-2 text-sm font-medium transition-colors ${
              isActive
                ? 'bg-bg-tertiary text-text-primary border-l-2 border-accent pl-[10px]'
                : 'text-text-secondary hover:bg-bg-tertiary/50 hover:text-text-primary border-l-2 border-transparent pl-[10px]'
            }`
          }
        >
          <Settings size={17} strokeWidth={1.8} className="shrink-0" />
          <span className="flex-1">Einstellungen</span>
        </NavLink>
      </div>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-border-subtle">
        <p className="text-[10px] text-text-tertiary">SentinelClaw &middot; NVIDIA NemoClaw</p>
      </div>
    </aside>
  );
}
