// ── NemoClaw Workspace-Konfigurationsseite ──────────────────────────
//
// Zeigt und bearbeitet die Agent-Workspace-Dateien (SOUL.md, IDENTITY.md,
// USER.md, AGENTS.md, MEMORY.md) die in der OpenClaw-Sandbox gemountet werden.

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Brain, User, Users, Bot, Database, FileText, Save, X, Edit, Loader2 } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { api } from '../services/api';
import { MarkdownRenderer } from '../components/chat/MarkdownRenderer';

// ── Typen & Konfiguration ───────────────────────────────────────────

interface WorkspaceFile {
  name: string;
  content: string;
  size: number;
  modified_at: string;
}

interface FileConfig {
  icon: LucideIcon;
  label: string;
  description: string;
}

/** Mapping von Dateinamen zu Icon, Label und Kurzbeschreibung */
const FILE_CONFIG: Record<string, FileConfig> = {
  'SOUL.md': { icon: Brain, label: 'Soul', description: 'Persönlichkeit & Verhaltensregeln' },
  'IDENTITY.md': { icon: User, label: 'Identity', description: 'Name, Rolle & Selbstdarstellung' },
  'USER.md': { icon: Users, label: 'User', description: 'User-Präferenzen & gelernte Fakten' },
  'AGENTS.md': { icon: Bot, label: 'Agents', description: 'Multi-Agent-Koordination' },
  'MEMORY.md': { icon: Database, label: 'Memory', description: 'Langzeit-Gedächtnis' },
};

// ── Dateiliste (Sidebar) ────────────────────────────────────────────

interface FileListProps {
  files: WorkspaceFile[];
  selectedFile: string;
  onSelect: (name: string) => void;
}

function FileList({ files, selectedFile, onSelect }: FileListProps) {
  return (
    <div className="space-y-0.5">
      {files.map((file) => {
        const config = FILE_CONFIG[file.name];
        const Icon = config?.icon ?? FileText;
        const isActive = file.name === selectedFile;

        return (
          <button
            key={file.name}
            onClick={() => onSelect(file.name)}
            className={`w-full flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors text-left ${
              isActive
                ? 'bg-bg-tertiary text-text-primary border-l-2 border-accent pl-[10px]'
                : 'text-text-secondary hover:bg-bg-tertiary/50 hover:text-text-primary border-l-2 border-transparent pl-[10px]'
            }`}
          >
            <Icon size={17} strokeWidth={1.8} className="shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="truncate">{config?.label ?? file.name}</p>
              <p className="text-[11px] text-text-tertiary truncate">{config?.description ?? ''}</p>
            </div>
          </button>
        );
      })}
    </div>
  );
}

// ── Editor-Ansicht ──────────────────────────────────────────────────

interface EditorProps {
  content: string;
  onChange: (value: string) => void;
  onSave: () => void;
  onCancel: () => void;
  isSaving: boolean;
}

function WorkspaceEditor({ content, onChange, onSave, onCancel, isSaving }: EditorProps) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border-subtle bg-bg-tertiary/50">
        <button
          onClick={onSave}
          disabled={isSaving}
          className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {isSaving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
          Speichern
        </button>
        <button
          onClick={onCancel}
          disabled={isSaving}
          className="flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
        >
          <X size={14} />
          Abbrechen
        </button>
      </div>
      <textarea
        value={content}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 w-full p-4 bg-bg-primary text-text-primary text-sm font-mono leading-relaxed resize-none focus:outline-none"
        spellCheck={false}
      />
    </div>
  );
}

// ── Hauptkomponente ─────────────────────────────────────────────────

export function WorkspacePage() {
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState('SOUL.md');
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Alle Workspace-Dateien laden
  const { data: files = [], isLoading, error } = useQuery({
    queryKey: ['workspace'],
    queryFn: () => api.workspace.list(),
  });

  // Mutation zum Speichern
  const updateMutation = useMutation({
    mutationFn: ({ name, content }: { name: string; content: string }) =>
      api.workspace.update(name, content),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['workspace'] });
      setIsEditing(false);
      setStatusMessage({ type: 'success', text: `${variables.name} erfolgreich gespeichert` });
      setTimeout(() => setStatusMessage(null), 4000);
    },
    onError: (err: Error) => {
      setStatusMessage({ type: 'error', text: `Fehler: ${err.message}` });
      setTimeout(() => setStatusMessage(null), 6000);
    },
  });

  const currentFile = files.find((f) => f.name === selectedFile);

  /** Wechselt in den Bearbeitungsmodus */
  function startEditing() {
    if (!currentFile) return;
    setEditContent(currentFile.content);
    setIsEditing(true);
    setStatusMessage(null);
  }

  /** Speichert die Änderungen */
  function handleSave() {
    updateMutation.mutate({ name: selectedFile, content: editContent });
  }

  /** Bricht die Bearbeitung ab */
  function handleCancel() {
    setIsEditing(false);
    setEditContent('');
    setStatusMessage(null);
  }

  /** Datei wechseln — verlässt ggf. den Editor */
  function handleSelectFile(name: string) {
    if (isEditing) {
      setIsEditing(false);
      setEditContent('');
    }
    setSelectedFile(name);
    setStatusMessage(null);
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Workspace</h1>
          <p className="text-xs text-text-tertiary mt-0.5">
            NemoClaw/OpenClaw Agent-Konfiguration
          </p>
        </div>
        {currentFile && !isEditing && (
          <button
            onClick={startEditing}
            className="flex items-center gap-1.5 rounded-md border border-border-subtle px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary hover:bg-bg-tertiary transition-colors"
          >
            <Edit size={14} />
            Bearbeiten
          </button>
        )}
      </div>

      {/* Status-Meldung */}
      {statusMessage && (
        <div className={`mx-6 mt-3 rounded-md px-3 py-2 text-xs font-medium ${
          statusMessage.type === 'success'
            ? 'bg-status-success/10 text-status-success border border-status-success/20'
            : 'bg-status-error/10 text-status-error border border-status-error/20'
        }`}>
          {statusMessage.text}
        </div>
      )}

      {/* Inhalt */}
      <div className="flex-1 flex min-h-0">
        {/* Dateiliste (Sidebar) */}
        <div className="w-56 shrink-0 border-r border-border-subtle p-3 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center gap-2 px-3 py-4 text-sm text-text-tertiary">
              <Loader2 size={16} className="animate-spin" />
              Lade Dateien...
            </div>
          ) : error ? (
            <p className="px-3 py-4 text-sm text-status-error">
              Fehler beim Laden: {(error as Error).message}
            </p>
          ) : (
            <FileList files={files} selectedFile={selectedFile} onSelect={handleSelectFile} />
          )}
        </div>

        {/* Datei-Ansicht / Editor */}
        <div className="flex-1 min-w-0 overflow-hidden">
          {isEditing ? (
            <WorkspaceEditor
              content={editContent}
              onChange={setEditContent}
              onSave={handleSave}
              onCancel={handleCancel}
              isSaving={updateMutation.isPending}
            />
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
