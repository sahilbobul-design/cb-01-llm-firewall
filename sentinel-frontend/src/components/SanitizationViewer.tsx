import React from 'react';
import { Sparkles, Shield, ArrowRight, Copy, Check } from 'lucide-react';

interface SanitizationViewerProps {
  originalContent: string;
  sanitizedContent: string;
  redactionsCount: number;
  isBlocked: boolean;
}

export const SanitizationViewer: React.FC<SanitizationViewerProps> = ({
  originalContent,
  sanitizedContent,
  redactionsCount,
  isBlocked,
}) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(sanitizedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Render tokens with highlighting
  const renderHighlightedContent = (text: string) => {
    if (!text) return <span className="text-slate-500 italic">No content</span>;

    const parts = text.split(/(\[REDACTED_[A-Z0-9_]+\]|\[BLOCKED_BY_SECURITY_GATEWAY\])/g);
    return parts.map((part, index) => {
      if (part === '[BLOCKED_BY_SECURITY_GATEWAY]') {
        return (
          <span
            key={index}
            className="inline-block px-2 py-0.5 my-0.5 rounded font-bold font-mono text-xs bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.3)]"
          >
            {part}
          </span>
        );
      }
      if (part.startsWith('[REDACTED_')) {
        return (
          <span
            key={index}
            className="inline-block px-1.5 py-0.5 my-0.5 rounded font-mono text-xs bg-amber-500/20 text-amber-300 border border-amber-500/40"
          >
            {part}
          </span>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
            Content Sanitization & Redaction Engine
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
            {redactionsCount} Redaction{redactionsCount === 1 ? '' : 's'} Applied
          </span>
          <button
            onClick={handleCopy}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Copy Sanitized Content"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* LEFT: ORIGINAL INPUT */}
        <div className="flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono text-slate-400 uppercase font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> Original Untrusted Input
            </span>
            <span className="text-[10px] font-mono text-slate-400">RAW DATA</span>
          </div>
          <div className="flex-1 p-3.5 rounded-xl border border-slate-800/80 bg-slate-950/60 font-mono text-xs text-slate-300 leading-relaxed overflow-y-auto max-h-56 min-h-[140px] whitespace-pre-wrap">
            {originalContent || <span className="text-slate-400 italic">No input text</span>}
          </div>
        </div>

        {/* RIGHT: SANITIZED OUTPUT */}
        <div className="flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono text-slate-400 uppercase font-bold flex items-center gap-1.5">
              <Shield className="w-3 h-3 text-cyan-400" /> Sanitized LLM-Safe Payload
            </span>
            <span className={`text-[10px] font-mono font-bold ${isBlocked ? 'text-rose-400' : 'text-emerald-400'}`}>
              {isBlocked ? 'BLOCKED STREAM' : 'READY FOR MODEL'}
            </span>
          </div>
          <div className="flex-1 p-3.5 rounded-xl border border-cyan-500/20 bg-slate-950/80 font-mono text-xs text-slate-200 leading-relaxed overflow-y-auto max-h-56 min-h-[140px] whitespace-pre-wrap shadow-[inset_0_0_15px_rgba(0,0,0,0.5)]">
            {renderHighlightedContent(sanitizedContent)}
          </div>
        </div>
      </div>
    </div>
  );
};
