// ── NemoClaw Workspace-Konfigurationsseite ──────────────────────────

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Brain, User, Users, Bot, Database, FileText, Edit, Loader2, RefreshCw, Download } from 'lucide-react';
import { api } from '../services/api';
import { nemoclawApi } from '../services/api/agent-api';
import { MarkdownRenderer } from '../components/chat/MarkdownRenderer';
import { FileList, WorkspaceEditor } from '../components/workspace/WorkspaceEditor';
import type { FileConfig } from '../components/workspace/WorkspaceEditor';

const FILE_CONFIG: Record<string, FileConfig> = {
  'SOUL.md': { icon: Brain, label: 'Soul', description: 'Persönlichkeit & Verhaltensregeln' },
  'IDENTITY.md': { icon: User, label: 'Identity', description: 'Name, Rolle & Selbstdarstellung' },
  'USER.md': { icon: Users, label: 'User', description: 'User-Präferenzen & gelernte Fakten' },
  'AGENTS.md': { icon: Bot, label: 'Agents', description: 'Multi-Agent-Koordination' },
  'MEMORY.md': { icon: Database, label: 'Memory', description: 'Langzeit-Gedächtnis' },
};

export function WorkspacePage() {
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState('SOUL.md');
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [pulling, setPulling] = useState(false);

  const { data: files = [], isLoading, error } = useQuery({
    queryKey: ['workspace'],
    queryFn: () => api.workspace.list(),
  });

  const updateMutation = useMutation({
    mutationFn: ({ name, content }: { name: string; content: string }) =>
      api.workspace.update(name, content),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['workspace'] });
      setIsEditing(false);
      showStatus('success', `${variables.name} erfolgreich gespeichert`);
    },
    onError: (err: Error) => showStatus('error', `Fehler: ${err.message}`),
  });

  const currentFile = files.find((f) => f.name === selectedFile);

  function showStatus(type: 'success' | 'error', text: string) {
    setStatusMessage({ type, text });
    setTimeout(() => setStatusMessage(null), 5000);
  }

  async function handleSyncConfig() {
    setSyncing(true);
    setStatusMessage(null);
    try {
      const result = await nemoclawApi.syncConfig();
      showStatus(result.success ? 'success' : 'error',
        result.success ? 'Sandbox-Konfiguration synchronisiert' : result.message);
    } catch {
      showStatus('error', 'Verbindung zum Server fehlgeschlagen.');
    } finally {
      setSyncing(false);
    }
  }

  async function handlePullMemory() {
    setPulling(true);
    setStatusMessage(null);
    try {
      const result = await nemoclawApi.pullMemory();
      showStatus(result.success ? 'success' : 'error',
        result.success ? 'Agent-Erinnerungen in MEMORY.md übernommen' : result.message);
      if (result.success) queryClient.invalidateQueries({ queryKey: ['workspace'] });
    } catch {
      showStatus('error', 'Verbindung zum Server fehlgeschlagen.');
    } finally {
      setPulling(false);
    }
  }

  function handleSelectFile(name: string) {
    if (isEditing) { setIsEditing(false); setEditContent(''); }
    setSelectedFile(name);
    setStatusMessage(null);
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Workspace</h1>
          <p className="text-xs text-text-tertiary mt-0.5">NemoClaw/OpenClaw Agent-Konfiguration</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleSyncConfig} disabled={syncing}
            className="flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors disabled:opacity-50">
            <RefreshCw size={14} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Synchronisiere...' : 'Sandbox aktualisieren'}
          </button>
          <button onClick={handlePullMemory} disabled={pulling}
            className="flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors disabled:opacity-50">
            <Download size={14} className={pulling ? 'animate-bounce' : ''} />
            {pulling ? 'Lade...' : 'Memory laden'}
          </button>
          {currentFile && !isEditing && (
            <button onClick={() => { setEditContent(currentFile.content); setIsEditing(true); setStatusMessage(null); }}
              className="flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors">
              <Edit size={14} /> Bearbeiten
            </button>
          )}
        </div>
      </div>

      {/* Status-Meldung */}
      {statusMessage && (
        <div className={`mx-6 mt-3 rounded-md px-3 py-2 text-xs font-medium ${
          statusMessage.type === 'success'
            ? 'bg-status-success/10 text-status-success border border-status-success/20'
            : 'bg-status-error/10 text-status-error border border-status-error/20'
        }`}>{statusMessage.text}</div>
      )}

      {/* Inhalt */}
      <div className="flex-1 flex min-h-0">
        <div className="w-56 shrink-0 border-r border-border-subtle p-3 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center gap-2 px-3 py-4 text-sm text-text-tertiary">
              <Loader2 size={16} className="animate-spin" /> Lade Dateien...
            </div>
          ) : error ? (
            <p className="px-3 py-4 text-sm text-status-error">
              Fehler beim Laden: {(error as Error).message}
            </p>
          ) : (
            <FileList files={files} selectedFile={selectedFile} onSelect={handleSelectFile} fileConfig={FILE_CONFIG} />
          )}
        </div>

        <div className="flex-1 min-w-0 overflow-hidden">
          {isEditing ? (
            <WorkspaceEditor content={editContent} onChange={setEditContent}
              onSave={() => updateMutation.mutate({ name: selectedFile, content: editContent })}
              onCancel={() => { setIsEditing(false); setEditContent(''); setStatusMessage(null); }}
              isSaving={updateMutation.isPending} />
          ) : currentFile ? (
            <div className="h-full overflow-y-auto p-6">
              <div className="flex items-center gap-2 mb-4 text-text-tertiary text-[11px]">
                <FileText size={13} />
                <span>{currentFile.name}</span>
                <span className="mx-1">&middot;</span>
                <span>{currentFile.size} Bytes</span>
                <span className="mx-1">&middot;</span>
                <span>Geändert: {new Date(currentFile.modified_at).toLocaleString('de-DE')}</span>
              </div>
              <MarkdownRenderer content={currentFile.content} />
            </div>
          ) : (
            <div className="flex items-center justify-center h-full text-text-tertiary text-sm">
              Keine Datei ausgewählt
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
