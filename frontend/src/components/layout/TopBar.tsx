import { Shield, Zap, Menu, MessageSquare } from 'lucide-react';
import { useKill } from '../../hooks/useApi';

interface TopBarProps {
  systemOnline: boolean;
  onMenuToggle?: () => void;
  chatOpen?: boolean;
  onChatToggle?: () => void;
}

export function TopBar({ systemOnline, onMenuToggle, chatOpen, onChatToggle }: TopBarProps) {
  const killMutation = useKill();

  function handleKill() {
    if (!confirm('NOTAUS\n\nAlle laufenden Scans sofort stoppen?')) return;
    killMutation.mutate('Kill Switch über Web-UI');
  }

  return (
    <header className="h-14 shrink-0 border-b border-border-subtle bg-bg-secondary flex items-center justify-between px-3 sm:px-5 gap-2">
      {/* Links: Hamburger + Logo */}
      <div className="flex items-center gap-2 sm:gap-3">
        <button
          onClick={onMenuToggle}
          className="lg:hidden p-1.5 rounded-md text-text-secondary hover:text-text-primary hover:bg-bg-tertiary"
          aria-label="Menü"
        >
          <Menu size={20} />
        </button>

        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent/10 text-accent">
          <Shield size={18} strokeWidth={2} />
        </div>
        <span className="text-sm font-semibold tracking-wide text-text-primary">
          <span className="sm:hidden">SC</span>
          <span className="hidden sm:inline">SentinelClaw</span>
        </span>
        <span className="hidden sm:inline text-[10px] font-medium text-text-tertiary tracking-widest uppercase">v0.1</span>
      </div>

      {/* Rechts: Chat-Toggle + Status + Kill */}
      <div className="flex items-center gap-2 sm:gap-4">
        {/* Chat-Toggle-Button */}
        <button
          onClick={onChatToggle}
          className={`hidden lg:flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors ${
            chatOpen
              ? 'bg-accent/15 text-accent'
              : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary'
          }`}
          aria-label="Agent Chat"
        >
          <MessageSquare size={14} strokeWidth={2} />
          <span>Chat</span>
        </button>

        <div className="flex items-center gap-1.5 text-xs text-text-secondary">
          <span className={`h-2 w-2 rounded-full shrink-0 ${
            systemOnline
              ? 'bg-status-success shadow-[0_0_6px_rgba(34,197,94,0.4)]'
              : 'bg-status-error shadow-[0_0_6px_rgba(239,68,68,0.4)]'
          }`} />
          <span className="hidden sm:inline">{systemOnline ? 'Online' : 'Offline'}</span>
        </div>

        <button
          onClick={handleKill}
          disabled={killMutation.isPending}
          className="flex items-center gap-1.5 rounded-md border border-severity-critical/30 bg-severity-critical/10 px-2 sm:px-3 py-1.5 text-[11px] font-semibold text-severity-critical uppercase hover:bg-severity-critical/20 disabled:opacity-50"
        >
          <Zap size={13} strokeWidth={2.5} />
          <span className="hidden sm:inline">{killMutation.isPending ? '...' : 'Kill'}</span>
        </button>
      </div>
    </header>
  );
}
