// ── Verbessertes Markdown-Rendering mit Syntax-Highlighting ─────────

import { useState, useCallback } from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

interface MarkdownRendererProps {
  content: string;
  compact?: boolean;
}

// ── Copy-Button für Code-Blöcke ─────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="absolute top-2 right-2 rounded-md p-1.5 text-text-tertiary hover:text-text-primary hover:bg-white/10 transition-colors opacity-0 group-hover:opacity-100"
      title="Kopieren"
    >
      {copied ? <Check size={13} className="text-status-success" /> : <Copy size={13} />}
    </button>
  );
}

// ── Hauptkomponente ─────────────────────────────────────────────────

export function MarkdownRenderer({ content, compact = false }: MarkdownRendererProps) {
  const textSize = compact ? 'text-[13px]' : 'text-sm';

  return (
    <div className={`${textSize} leading-relaxed text-text-primary prose prose-invert ${compact ? 'prose-sm' : ''} max-w-none
      prose-p:my-1.5 prose-li:my-0.5 prose-ul:my-1 prose-ol:my-1
      prose-strong:text-text-primary prose-strong:font-semibold
      prose-headings:text-text-primary prose-headings:mt-3 prose-headings:mb-1.5
      prose-a:text-accent prose-a:no-underline hover:prose-a:underline
      prose-hr:border-border-subtle prose-blockquote:border-accent/40
      prose-table:border-collapse`}>
      <Markdown
        remarkPlugins={[remarkGfm]}
        components={{
          // Code-Blöcke mit Syntax-Highlighting
          code({ className, children, ...props }) {
            const match = /language-(\w+)/.exec(className || '');
            const codeText = String(children).replace(/\n$/, '');

            // Inline-Code (kein Sprach-Marker und kein Zeilenumbruch)
            if (!match && !codeText.includes('\n')) {
              return (
                <code
                  className="text-accent bg-accent/10 px-1.5 py-0.5 rounded text-[12px] font-mono"
                  {...props}
                >
                  {children}
                </code>
              );
            }

            // Code-Block mit Syntax-Highlighting
            const language = match?.[1] || 'text';
            return (
              <div className="group relative my-3 rounded-lg overflow-hidden border border-border-subtle">
                {/* Sprach-Label */}
                <div className="flex items-center justify-between px-3 py-1.5 bg-bg-tertiary border-b border-border-subtle">
                  <span className="text-[10px] font-mono text-text-tertiary uppercase tracking-wider">
                    {language}
                  </span>
                </div>
                <CopyButton text={codeText} />
                <SyntaxHighlighter
                  style={oneDark}
                  language={language}
                  PreTag="div"
                  customStyle={{
                    margin: 0,
                    padding: '0.75rem 1rem',
                    background: 'transparent',
                    fontSize: '12px',
                    lineHeight: '1.6',
                  }}
                >
                  {codeText}
                </SyntaxHighlighter>
              </div>
            );
          },

          // Tabellen mit Tailwind-Styling
          table({ children }) {
            return (
              <div className="overflow-x-auto my-3 rounded-lg border border-border-subtle">
                <table className="w-full text-xs">{children}</table>
              </div>
            );
          },
          thead({ children }) {
            return <thead className="bg-bg-tertiary">{children}</thead>;
          },
          th({ children }) {
            return (
              <th className="px-3 py-2 text-left text-[11px] font-semibold text-text-secondary border-b border-border-subtle">
                {children}
              </th>
            );
          },
          td({ children }) {
            return (
              <td className="px-3 py-2 text-text-primary border-b border-border-subtle">
                {children}
              </td>
            );
          },
          tr({ children }) {
            return <tr className="hover:bg-bg-tertiary/50 transition-colors">{children}</tr>;
          },

          // Links mit externem Icon
          a({ href, children }) {
            return (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline"
              >
                {children}
              </a>
            );
          },

          // Blockquotes mit Accent-Border
          blockquote({ children }) {
            return (
              <blockquote className="border-l-2 border-accent/40 pl-3 my-2 text-text-secondary italic">
                {children}
              </blockquote>
            );
          },
        }}
      >
        {content}
      </Markdown>
    </div>
  );
}
