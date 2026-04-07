// Generische Ergebnis-Sektion für den Scan-Vergleich

interface CompareSectionProps<T> {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  borderColor: string;
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
}

/** Klappt eine Liste von Findings/Items in eine farbcodierte Sektion */
export function CompareSection<T>({
  title,
  subtitle,
  icon,
  color,
  bgColor,
  borderColor,
  items = [] as unknown as T[],
  renderItem,
}: CompareSectionProps<T>) {
  return (
    <div className={`rounded-lg border ${borderColor} ${bgColor} overflow-hidden`}>
      <div className="px-5 py-3 border-b border-border-subtle flex items-center gap-2">
        <span className={color}>{icon}</span>
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        <span className="text-xs text-text-tertiary">({items.length})</span>
        <span className="text-xs text-text-tertiary ml-1">&mdash; {subtitle}</span>
      </div>
      {items.length === 0 ? (
        <p className="px-5 py-4 text-xs text-text-tertiary">None</p>
      ) : (
        <div className="divide-y divide-border-subtle">{items.map(renderItem)}</div>
      )}
    </div>
  );
}
