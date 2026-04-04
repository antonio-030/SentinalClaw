// ── Chat-Eingabefeld mit Senden-Button ──────────────────────────────
// Mobile-optimiert: Größere Touch-Targets, expliziter button type

import { useState, useRef } from 'react';
import { Send } from 'lucide-react';

interface ChatInputProps {
  onSend: (message: string) => void;
  disabled?: boolean;
}

export function ChatInput({ onSend, disabled = false }: ChatInputProps) {
  const [value, setValue] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  function doSend() {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setValue('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  }

  return (
    <div className="flex items-end gap-2 p-3 border-t border-border-subtle bg-bg-secondary">
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          const el = e.target;
          el.style.height = 'auto';
          el.style.height = Math.min(el.scrollHeight, 120) + 'px';
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            doSend();
          }
        }}
        disabled={disabled}
        placeholder="Nachricht eingeben..."
        rows={1}
        className="flex-1 resize-none rounded-lg border border-border-subtle bg-bg-primary px-3 py-2.5 text-sm text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-accent/50 disabled:opacity-50"
      />
      <button
        type="button"
        onClick={doSend}
        onTouchEnd={(e) => {
          e.preventDefault();
          doSend();
        }}
        disabled={disabled}
        className="shrink-0 flex items-center justify-center h-11 w-11 rounded-lg bg-accent text-white active:bg-accent/80 disabled:opacity-30 disabled:cursor-not-allowed touch-manipulation"
        aria-label="Senden"
      >
        <Send size={18} strokeWidth={2.5} />
      </button>
    </div>
  );
}
