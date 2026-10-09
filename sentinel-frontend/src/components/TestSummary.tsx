import React from 'react';
import { CheckCircle2, XCircle, MinusCircle, Percent, ShieldCheck } from 'lucide-react';
import { TestSummaryStats } from '../types/test';

interface TestSummaryProps {
  stats: TestSummaryStats;
  currentRunningIndex?: number;
  totalRunning?: number;
}

export const TestSummary: React.FC<TestSummaryProps> = ({ stats, currentRunningIndex, totalRunning }) => {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
          Suite Execution Diagnostics & Pass Rate
        </span>
        {totalRunning && totalRunning > 0 ? (
          <span className="text-xs font-mono text-cyan-400 animate-pulse">
            Testing in progress: {currentRunningIndex} / {totalRunning}
          </span>
        ) : (
          <span className="text-xs font-mono text-slate-400">Automated Validation</span>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {/* TOTAL */}
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-center">
          <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">Total Test Cases</span>
          <span className="text-2xl font-extrabold font-mono text-white">{stats.total}</span>
        </div>

        {/* PASSED */}
        <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-center">
          <span className="text-[10px] uppercase font-mono text-emerald-400 block mb-1 flex items-center justify-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Passed
          </span>
          <span className="text-2xl font-extrabold font-mono text-emerald-400">{stats.passed}</span>
        </div>

        {/* FAILED */}
        <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/30 text-center">
          <span className="text-[10px] uppercase font-mono text-rose-400 block mb-1 flex items-center justify-center gap-1">
            <XCircle className="w-3 h-3" /> Failed
          </span>
          <span className="text-2xl font-extrabold font-mono text-rose-400">{stats.failed}</span>
        </div>

        {/* UNAVAILABLE */}
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-center">
          <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1 flex items-center justify-center gap-1">
            <MinusCircle className="w-3 h-3" /> Unavailable
          </span>
          <span className="text-2xl font-extrabold font-mono text-slate-400">{stats.unavailable}</span>
        </div>

        {/* PASS RATE */}
        <div className="p-3 rounded-xl bg-cyan-950/20 border border-cyan-500/30 text-center">
          <span className="text-[10px] uppercase font-mono text-cyan-400 block mb-1 flex items-center justify-center gap-1">
            <Percent className="w-3 h-3" /> Pass Rate
          </span>
          <span className="text-2xl font-extrabold font-mono text-cyan-300">
            {stats.total > 0 ? `${stats.passRate.toFixed(1)}%` : '0%'}
          </span>
        </div>
      </div>
    </div>
  );
};
