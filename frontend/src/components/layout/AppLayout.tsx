import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { MessageSquare } from 'lucide-react';
import { useStatus } from '../../hooks/useApi';
import { TopBar } from './TopBar';
import { Sidebar } from './Sidebar';
import { ChatPanel } from '../chat/ChatPanel';

export function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);

  const { data: status } = useStatus();

  const systemOnline = !!status;
  const runningScans = status?.scans.running ?? 0;

  return (
    <div className="flex h-[100dvh] w-full flex-col bg-bg-primary">
      <TopBar
        systemOnline={systemOnline}
        onMenuToggle={() => setSidebarOpen(!sidebarOpen)}
        chatOpen={chatOpen}
        onChatToggle={() => setChatOpen(!chatOpen)}
      />
      <div className="flex flex-1 overflow-hidden relative">
        {/* Mobile Overlay — Sidebar */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/60 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Sidebar — Desktop: immer sichtbar, Mobile: Slide-Over */}
        <div className={`
          fixed inset-y-0 left-0 z-40 w-64 transform transition-transform duration-200 ease-out
          lg:static lg:z-auto lg:translate-x-0 lg:w-60
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}>
          <Sidebar
            runningScans={runningScans}
            onNavigate={() => setSidebarOpen(false)}
          />
        </div>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>

        {/* Chat Panel — Desktop: rechtes Panel, Mobile: Slide-Over */}
        <ChatPanel isOpen={chatOpen} onClose={() => setChatOpen(false)} />
      </div>

      {/* Mobile: Chat-Bubble-Button (unten rechts, nur wenn Chat geschlossen) */}
      {!chatOpen && (
        <button
          onClick={() => setChatOpen(true)}
          className="fixed bottom-5 right-5 z-30 lg:hidden flex items-center justify-center w-14 h-14 rounded-full bg-accent text-white shadow-lg shadow-accent/25 hover:bg-accent/90 active:scale-95 transition-all"
          aria-label="Chat oeffnen"
        >
          <MessageSquare size={22} strokeWidth={2} />
        </button>
      )}
    </div>
  );
}
