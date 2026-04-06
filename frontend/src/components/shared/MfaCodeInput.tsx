// ── MFA Code-Eingabe Formular ────────────────────────────────────────
// Wiederverwendbare Komponente für die TOTP-Code-Eingabe.
// Wird auf der Login-Seite und potenziell in den Einstellungen verwendet.

import { useRef, type FormEvent } from 'react';
import { KeyRound, Loader2, AlertTriangle } from 'lucide-react';

interface MfaCodeInputProps {
  mfaCode: string;
  onMfaCodeChange: (code: string) => void;
  error: string | null;
  loading: boolean;
  onSubmit: (e: FormEvent) => void;
  onBack?: () => void;
}

export function MfaCodeInput({
  mfaCode,
  onMfaCodeChange,
  error,
  loading,
  onSubmit,
  onBack,
}: MfaCodeInputProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-xl border border-border-subtle bg-bg-secondary p-6 sm:p-8 shadow-2xl shadow-black/30"
    >
      <div className="mb-6 flex items-center gap-2.5">
        <KeyRound size={18} className="text-accent" strokeWidth={1.8} />
        <h2 className="text-sm font-semibold text-text-secondary tracking-wide uppercase">
          Zwei-Faktor-Authentifizierung
        </h2>
      </div>

      <p className="mb-5 text-xs text-text-tertiary leading-relaxed">
        Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein.
      </p>

      {/* Fehlermeldung */}
      {error && (
        <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-severity-critical/20 bg-severity-critical/5 px-3.5 py-3 text-xs text-severity-critical">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" strokeWidth={2} />
          <span>{error}</span>
        </div>
      )}

      <label className="mb-6 block">
        <span className="mb-1.5 block text-[11px] font-medium text-text-tertiary uppercase tracking-wider">
          TOTP-Code
        </span>
        <input
          ref={inputRef}
          type="text"
          inputMode="numeric"
          pattern="[0-9]{6}"
          maxLength={6}
          required
          autoFocus
          autoComplete="one-time-code"
          placeholder="000000"
          value={mfaCode}
          onChange={(e) => {
            // Nur Ziffern zulassen
            const digits = e.target.value.replace(/\D/g, '').slice(0, 6);
            onMfaCodeChange(digits);
          }}
          className="w-full rounded-lg border border-border-default bg-bg-primary px-3.5 py-2.5 text-center text-lg font-mono tracking-[0.3em] text-text-primary placeholder:text-text-tertiary/40 outline-none transition-colors focus:border-accent focus:ring-1 focus:ring-accent/30"
        />
      </label>

      <button
        type="submit"
        disabled={loading || mfaCode.length !== 6}
        className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? (
          <>
            <Loader2 size={16} className="animate-spin" />
            Authentifizierung...
          </>
        ) : (
          'Verifizieren'
        )}
      </button>

      {onBack && (
        <button
          type="button"
          onClick={onBack}
          className="mt-3 flex w-full items-center justify-center text-xs text-text-tertiary hover:text-text-secondary transition-colors"
        >
          Zurück zur Anmeldung
        </button>
      )}
    </form>
  );
}
