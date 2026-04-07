// Wiederverwendbare Workspace-Komponenten: Dateiliste und Editor

import { FileText, Save, X, Loader2 } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// ── Typen ──────────────────────────────────────────────────────────

export interface WorkspaceFile {
  name: string;
  content: string;
  size: number;
  modified_at: string;
}

export interface FileConfig {
  icon: LucideIcon;
  label: string;
  description: string;
}

// ── Dateiliste (Sidebar) ───────────────────────────────────────────

interface FileListProps {
  files: WorkspaceFile[];
  selectedFile: string;
  onSelect: (name: string) => void;
  fileConfig: Record<string, FileConfig>;
}

export function FileList({ files, selectedFile, onSelect, fileConfig }: FileListProps) {
  return (
    <div className="space-y-0.5">
      {files.map((file) => {
        const config = fileConfig[file.name];
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

// ── Editor-Ansicht ─────────────────────────────────────────────────

interface EditorProps {
  content: string;
  onChange: (value: string) => void;
  onSave: () => void;
  onCancel: () => void;
  isSaving: boolean;
}

export function WorkspaceEditor({ content, onChange, onSave, onCancel, isSaving }: EditorProps) {
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
