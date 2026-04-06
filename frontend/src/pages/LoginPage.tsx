// ── SentinelClaw Login Page ──────────────────────────────────────────
// Zweistufiger Login: Passwort-Eingabe, dann optional MFA-Code-Eingabe
// wenn der Benutzer TOTP aktiviert hat.

import { useState, type FormEvent } from 'react';
import { Shield, Eye, EyeOff, Loader2, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import { useAuthStore } from '../stores/authStore';
import { MfaCodeInput } from '../components/shared/MfaCodeInput';

export function LoginPage() {
  const login = useAuthStore((s) => s.login);

  // Schritt 1: Anmeldedaten
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Schritt 2: MFA-Verifikation
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaSession, setMfaSession] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  // Gemeinsamer State
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleLoginSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.auth.login(email, password);

      if (res.mfa_required) {
        // MFA aktiv — zweiten Schritt anzeigen
        setMfaRequired(true);
        setMfaSession(res.mfa_session);
      } else {
        // Kein MFA — direkt einloggen
        login(res.token, res.user);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message.includes('401')
            ? 'Ungültige Anmeldedaten. Bitte versuchen Sie es erneut.'
            : err.message
          : 'Ein unbekannter Fehler ist aufgetreten.',
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleMfaSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.auth.mfaLogin(mfaSession, mfaCode);
      login(res.token, res.user);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message.includes('401')
            ? 'Ungültiger MFA-Code. Bitte erneut versuchen.'
            : err.message
          : 'Ein unbekannter Fehler ist aufgetreten.',
      );
      setMfaCode('');
    } finally {
      setLoading(false);
    }
  }

  function handleMfaBack() {
    setMfaRequired(false);
    setMfaSession('');
    setMfaCode('');
    setError(null);
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
          <div className="text-center">
            <h1 className="text-xl font-semibold tracking-tight text-text-primary">
              SentinelClaw
            </h1>
            <p className="mt-1 text-xs font-medium tracking-wide text-text-tertiary uppercase">
              AI-gestützte Security Assessment Platform
            </p>
          </div>
        </div>

        {/* Formular: Entweder Login oder MFA */}
        {mfaRequired ? (
          <MfaCodeInput
            mfaCode={mfaCode}
            onMfaCodeChange={setMfaCode}
            error={error}
            loading={loading}
            onSubmit={handleMfaSubmit}
            onBack={handleMfaBack}
          />
        ) : (
          <form
            onSubmit={handleLoginSubmit}
            className="rounded-xl border border-border-subtle bg-bg-secondary p-6 sm:p-8 shadow-2xl shadow-black/30"
          >
            <h2 className="mb-6 text-sm font-semibold text-text-secondary tracking-wide uppercase">
              Anmeldung
            </h2>

            {/* Fehlermeldung */}
            {error && (
              <div className="mb-5 flex items-start gap-2.5 rounded-lg border border-severity-critical/20 bg-severity-critical/5 px-3.5 py-3 text-xs text-severity-critical">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" strokeWidth={2} />
                <span>{error}</span>
              </div>
            )}

            {/* E-Mail */}
            <label className="mb-4 block">
              <span className="mb-1.5 block text-[11px] font-medium text-text-tertiary uppercase tracking-wider">
                E-Mail
              </span>
              <input
                type="email"
                required
                autoFocus
                autoComplete="email"
                placeholder="admin@sentinelclaw.local"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg border border-border-default bg-bg-primary px-3.5 py-2.5 text-sm text-text-primary placeholder:text-text-tertiary/60 outline-none transition-colors focus:border-accent focus:ring-1 focus:ring-accent/30"
              />
            </label>

            {/* Passwort */}
            <label className="mb-6 block">
              <span className="mb-1.5 block text-[11px] font-medium text-text-tertiary uppercase tracking-wider">
                Passwort
              </span>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  autoComplete="current-password"
                  placeholder="Passwort eingeben"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-border-default bg-bg-primary px-3.5 py-2.5 pr-10 text-sm text-text-primary placeholder:text-text-tertiary/60 outline-none transition-colors focus:border-accent focus:ring-1 focus:ring-accent/30"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 p-0.5 text-text-tertiary hover:text-text-secondary transition-colors"
                  tabIndex={-1}
                  aria-label={showPassword ? 'Passwort verbergen' : 'Passwort anzeigen'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </label>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || !email || !password}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Authentifizierung...
                </>
              ) : (
                'Anmelden'
              )}
            </button>
          </form>
        )}

        {/* Footer */}
        <p className="mt-6 text-center text-[10px] text-text-tertiary/60 tracking-wide">
          SentinelClaw v0.1 &mdash; Autorisierter Zugang erforderlich
        </p>
      </div>
    </div>
  );
}
