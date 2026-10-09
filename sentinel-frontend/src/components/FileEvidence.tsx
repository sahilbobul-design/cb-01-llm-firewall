import React from 'react';
import { FileCode, Hash, ShieldCheck, Bug, Copy, Check, ShieldAlert } from 'lucide-react';
import { FileSecurityInfo, ToolResultDetail } from '../types/scan';

interface FileEvidenceProps {
  fileSecurity: FileSecurityInfo;
  toolResults: Record<string, ToolResultDetail>;
}

export const FileEvidence: React.FC<FileEvidenceProps> = ({ fileSecurity, toolResults }) => {
  const [copied, setCopied] = React.useState(false);

  if (!fileSecurity || !fileSecurity.file_hash) {
    return null;
  }

  const handleCopyHash = () => {
    if (fileSecurity.file_hash) {
      navigator.clipboard.writeText(fileSecurity.file_hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const yaraRes = toolResults?.yara;
  const clamavRes = toolResults?.clamav;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-cyan-400" />
          <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
            File Security & Linux Forensics
          </span>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
          Quarantine Auto-Purged
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* HASH & METADATA */}
        <div className="space-y-3 p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
          <div>
            <span className="text-[10px] text-slate-400 uppercase block mb-1">Cryptographic SHA-256 Digest:</span>
            <div className="flex items-center justify-between bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 text-cyan-300 font-mono text-[11px] break-all">
              <span>{fileSecurity.file_hash}</span>
              <button onClick={handleCopyHash} className="ml-2 text-slate-400 hover:text-white" title="Copy SHA-256">
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-1 text-[11px]">
            <div>
              <span className="text-[10px] text-slate-400 uppercase block">MIME Type:</span>
              <span className="text-slate-200">{fileSecurity.mime_type || 'application/octet-stream'}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase block">File Size:</span>
              <span className="text-slate-200">{fileSecurity.file_size ? `${fileSecurity.file_size} bytes` : 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* LINUX SCANNERS STATUS */}
        <div className="grid grid-cols-2 gap-3">
          {/* YARA */}
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold font-mono text-slate-300 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400" /> YARA
              </span>
              <span
                className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                  yaraRes?.detected
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : yaraRes?.status === 'UNAVAILABLE'
                    ? 'bg-slate-800 text-slate-500'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}
              >
                {yaraRes?.status || fileSecurity.yara}
              </span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">
              {yaraRes?.matches && yaraRes.matches.length > 0 ? (
                <span className="text-rose-400">Match: {yaraRes.matches.join(', ')}</span>
              ) : (
                <span>0 pattern matches</span>
              )}
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-1">
              Time: {yaraRes?.execution_time_ms || 0}ms
            </div>
          </div>

          {/* ClamAV */}
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold font-mono text-slate-300 flex items-center gap-1.5">
                <Bug className="w-4 h-4 text-emerald-400" /> ClamAV
              </span>
              <span
                className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                  clamavRes?.infected
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : clamavRes?.status === 'UNAVAILABLE'
                    ? 'bg-slate-800 text-slate-500'
                    : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                }`}
              >
                {clamavRes?.status || fileSecurity.clamav}
              </span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono truncate" title={clamavRes?.signature}>
              {clamavRes?.signature ? (
                <span className="text-rose-400 font-bold">{clamavRes.signature}</span>
              ) : (
                <span>No virus found</span>
              )}
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-1">
              Time: {clamavRes?.execution_time_ms || 0}ms
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
