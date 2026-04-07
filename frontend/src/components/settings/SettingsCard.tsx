// Wiederverwendbare Hilfskomponenten für die Einstellungsseite

interface DotProps {
  ok: boolean;
}

/** Farbiger Punkt für Status-Anzeige (grün/rot) */
export function Dot({ ok }: DotProps) {
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full shrink-0 ${
        ok ? 'bg-status-success' : 'bg-status-error'
      }`}
    />
  );
}

interface StatusRowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

/** Einzelne Zeile innerhalb einer Karte: Label links, Wert rechts */
export function StatusRow({ label, value, mono = false }: StatusRowProps) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-border-subtle last:border-0">
      <span className="text-xs text-text-secondary">{label}</span>
      <span className={`text-xs text-text-primary text-right ${mono ? 'font-mono' : ''}`}>
        {value}
      </span>
    </div>
  );
}

interface CardProps {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
}

/** Einstellungs-Karte mit Icon-Header und Inhalt */
export function Card({ title, icon: Icon, children }: CardProps) {
  return (
    <section className="rounded-lg border border-border-subtle bg-bg-secondary">
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-border-subtle">
        <Icon size={16} strokeWidth={1.8} className="text-text-tertiary shrink-0" />
        <h2 className="text-sm font-semibold text-text-primary tracking-wide">{title}</h2>
      </div>
      <div className="px-5 py-3">{children}</div>
    </section>
  );
}
