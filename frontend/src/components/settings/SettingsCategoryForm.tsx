// Formular zum Bearbeiten aller Einstellungen einer Kategorie

import { useState } from 'react';
import { Loader2, Save, CheckCircle2 } from 'lucide-react';
import { useUpdateSettings } from '../../hooks/useApi';
import type { SystemSetting } from '../../types/api';
import { CategoryInfoBox } from './CategoryInfoBox';

interface SettingsCategoryFormProps {
  settings: SystemSetting[];
  category: string;
}

/** Rendert alle Einstellungen einer Kategorie als editierbares Formular */
export function SettingsCategoryForm({ settings, category }: SettingsCategoryFormProps) {
  const filtered = settings.filter((s) => s.category === category);
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(filtered.map((s) => [s.key, s.value])),
  );
  const [saved, setSaved] = useState(false);
  const updateMutation = useUpdateSettings();

  function handleChange(key: string, val: string) {
    setValues((prev) => ({ ...prev, [key]: val }));
    setSaved(false);
  }

  async function handleSave() {
    // Nur geänderte Werte senden
    const changed: Record<string, string> = {};
    for (const s of filtered) {
      if (values[s.key] !== s.value) changed[s.key] = values[s.key];
    }
    if (Object.keys(changed).length === 0) { setSaved(true); return; }
    await updateMutation.mutateAsync(changed);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  if (filtered.length === 0) {
    return <p className="text-xs text-text-tertiary py-4">Keine Einstellungen in dieser Kategorie.</p>;
  }

  return (
    <div className="space-y-3">
      {/* Kategorie-Info mit Beschreibung + optionalem Doku-Link */}
      <CategoryInfoBox category={category} />

      {filtered.map((s) => (
        <div key={s.key} className="rounded-md border border-border-subtle bg-bg-primary px-4 py-3">
          <label className="block text-xs font-medium text-text-primary mb-1">{s.label}</label>
          <p className="text-[10px] text-text-tertiary mb-2">{s.description}</p>
          {s.value_type === 'boolean' ? (
            <button
              type="button"
              onClick={() => handleChange(s.key, values[s.key] === 'true' ? 'false' : 'true')}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
                values[s.key] === 'true' ? 'bg-accent' : 'bg-border-default'
              }`}
              role="switch"
              aria-checked={values[s.key] === 'true'}
              aria-label={s.label}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${
                  values[s.key] === 'true' ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          ) : (
            <input
              type={s.value_type === 'int' || s.value_type === 'float' ? 'number' : 'text'}
              step={s.value_type === 'float' ? '0.1' : undefined}
              value={values[s.key] ?? ''}
              onChange={(e) => handleChange(s.key, e.target.value)}
              className="w-full rounded-md border border-border-default bg-bg-secondary px-3 py-1.5 text-xs text-text-primary font-mono focus:outline-none focus:ring-1 focus:ring-accent"
            />
          )}
        </div>
      ))}

      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={handleSave}
          disabled={updateMutation.isPending}
          className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-xs font-medium text-white hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {updateMutation.isPending ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <Save size={12} />
          )}
          Speichern
        </button>
        {saved && (
          <span className="flex items-center gap-1 text-xs text-status-success">
            <CheckCircle2 size={12} /> Gespeichert
          </span>
        )}
        {updateMutation.isError && (
          <span className="text-xs text-severity-critical">
            Fehler: {updateMutation.error?.message}
          </span>
        )}
      </div>
    </div>
  );
}
