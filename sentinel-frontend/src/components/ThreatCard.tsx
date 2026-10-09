import React from 'react';
import { AlertCircle, CheckCircle2 } from 'lucide-react';

interface ThreatCardProps {
  name: string;
  weight: number;
  detected: boolean;
  category: string;
}

export const ThreatCard: React.FC<ThreatCardProps> = ({ name, weight, detected, category }) => {
  return (
    <div
      className={`p-3 rounded-xl border transition-all ${
        detected
          ? 'border-rose-500/40 bg-rose-950/20 text-rose-300'
          : 'border-slate-800 bg-slate-950/40 text-slate-400 opacity-80'
      }`}
    >
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-xs font-bold text-slate-200">{name}</span>
        <span className="font-mono text-[10px] text-slate-400">+{weight}</span>
      </div>
      <div className="flex items-center justify-between text-[11px]">
        <span className="text-[10px] uppercase font-mono text-slate-400">{category}</span>
        {detected ? (
          <span className="flex items-center gap-1 text-[10px] font-bold text-rose-400">
            <AlertCircle className="w-3 h-3" /> DETECTED
          </span>
        ) : (
          <span className="flex items-center gap-1 text-[10px] text-emerald-400">
            <CheckCircle2 className="w-3 h-3" /> CLEAN
          </span>
        )}
      </div>
    </div>
  );
};
