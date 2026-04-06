// ── SentinelClaw Passwortänderung ──────────────────────────────────
// Erzwingt die Passwortänderung beim ersten Login (Standard-Admin)
// oder ermöglicht freiwillige Passwortänderung.

import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, Loader2, AlertTriangle, CheckCircle } from 'lucide-react';
import { api } from '../services/api';
import { useAuthStore } from '../stores/authStore';

const MIN_PASSWORD_LENGTH = 8;

export function ChangePasswordPage() {
  const navigate = useNavigate();
  const clearMustChangePassword = useAuthStore((s) => s.clearMustChangePassword);

  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showOld, setShowOld] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const passwordsMatch = newPassword === confirmPassword;
  const newLongEnough = newPassword.length >= MIN_PASSWORD_LENGTH;
  const canSubmit = oldPassword && newPassword && confirmPassword && passwordsMatch && newLongEnough;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setError(null);
    setLoading(true);

    try {
      await api.auth.changePassword(oldPassword, newPassword);
      clearMustChangePassword();
      navigate('/', { replace: true });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message.includes('401')
            ? 'Altes Passwort ist falsch.'
            : err.message
          : 'Ein unbekannter Fehler ist aufgetreten.',
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-[100dvh] w-full items-center justify-center bg-bg-primary p-4">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_-20%,rgba(59,130,246,0.08),transparent)]" />

      <div className="relative z-10 w-full max-w-md">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-accent/10 ring-1 ring-accent/20">
            <Shield size={28} strokeWidth={1.8} className="text-accent" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-text-primary">
            Passwort ändern
          </h1>
          <p className="text-xs text-text-tertiary text-center">
            Bitte ändere dein Passwort bevor du fortfährst.
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-xl border border-border-subtle bg-bg-secondary p-6 sm:p-8 shadow-2xl shadow-black/30"
        >
          {error && (
            <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-severity-critical/20 bg-severity-critical/5 px-3.5 py-3 text-xs text-severity-critical">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" strokeWidth={2} />
              <span>{error}</span>
            </div>
          )}

          {/* Altes Passwort */}
          <PasswordField
            label="Aktuelles Passwort"
            value={oldPassword}
            onChange={setOldPassword}
            show={showOld}
            onToggle={() => setShowOld(!showOld)}
            autoFocus
          />

          {/* Neues Passwort */}
          <PasswordField
            label="Neues Passwort"
            value={newPassword}
            onChange={setNewPassword}
            show={showNew}
            onToggle={() => setShowNew(!showNew)}
          />

          {/* Validierungshinweise */}
          <div className="mb-4 space-y-1 text-[11px]">
            <ValidationHint ok={newLongEnough} text={`Mindestens ${MIN_PASSWORD_LENGTH} Zeichen`} />
            <ValidationHint ok={passwordsMatch && confirmPassword.length > 0} text="Passwörter stimmen überein" />
          </div>

          {/* Passwort bestätigen */}
          <PasswordField
            label="Neues Passwort bestätigen"
            value={confirmPassword}
            onChange={setConfirmPassword}
            show={showNew}
            onToggle={() => setShowNew(!showNew)}
          />

          <button
            type="submit"
            disabled={loading || !canSubmit}
            className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Wird geändert...
              </>
            ) : (
              'Passwort ändern'
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Hilfskomponenten ────────────────────────────────────────────────

interface PasswordFieldProps {
  label: string;
  value: string;
  onChange: (v: string) => void;
  show: boolean;
  onToggle: () => void;
  autoFocus?: boolean;
}

function PasswordField({ label, value, onChange, show, onToggle, autoFocus }: PasswordFieldProps) {
  return (
    <label className="mb-4 block">
      <span className="mb-1.5 block text-[11px] font-medium text-text-tertiary uppercase tracking-wider">
        {label}
      </span>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          required
          autoFocus={autoFocus}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded-lg border border-border-default bg-bg-primary px-3.5 py-2.5 pr-10 text-sm text-text-primary placeholder:text-text-tertiary/60 outline-none transition-colors focus:border-accent focus:ring-1 focus:ring-accent/30"
        />
        <button
          type="button"
          onClick={onToggle}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 p-0.5 text-text-tertiary hover:text-text-secondary transition-colors"
          tabIndex={-1}
          aria-label={show ? 'Passwort verbergen' : 'Passwort anzeigen'}
        >
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </label>
  );
}

function ValidationHint({ ok, text }: { ok: boolean; text: string }) {
  return (
    <div className={`flex items-center gap-1.5 ${ok ? 'text-green-400' : 'text-text-tertiary'}`}>
      <CheckCircle size={12} strokeWidth={2} />
      <span>{text}</span>
    </div>
  );
}
