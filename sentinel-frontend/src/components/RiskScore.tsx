import React from 'react';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, AlertTriangle, Lock } from 'lucide-react';
import { RiskLevel } from '../types/scan';

interface RiskScoreProps {
  score: number;
  status: RiskLevel;
  breakdown: Record<string, number>;
  reasons: string[];
}

export const RiskScore: React.FC<RiskScoreProps> = ({ score, status, breakdown, reasons }) => {
  const isBlocked = status === 'BLOCKED' || score >= 70;
  const isSuspicious = status === 'SUSPICIOUS' || (score >= 30 && score < 70);
  const isSafe = status === 'SAFE' && score < 30;

  // Circle circumference: 2 * PI * 42 ~= 264
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const strokeOffset = circumference - (score / 100) * circumference;

  let strokeColor = '#10b981'; // safe
  let badgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  let badgeGlow = 'shadow-[0_0_20px_rgba(16,185,129,0.25)]';
  let statusIcon = <ShieldCheck className="w-5 h-5 text-emerald-400" />;

  if (isSuspicious) {
    strokeColor = '#f59e0b';
    badgeColor = 'bg-amber-500/10 text-amber-300 border-amber-500/30';
    badgeGlow = 'shadow-[0_0_20px_rgba(245,158,11,0.25)]';
    statusIcon = <AlertTriangle className="w-5 h-5 text-amber-400" />;
  } else if (isBlocked) {
    strokeColor = '#ef4444';
    badgeColor = 'bg-rose-500/15 text-rose-400 border-rose-500/40';
    badgeGlow = 'shadow-[0_0_30px_rgba(239,68,68,0.35)]';
    statusIcon = <ShieldAlert className="w-5 h-5 text-rose-400" />;
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
          Risk Assessment & Final Decision
        </span>
        <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-bold uppercase ${badgeColor} ${badgeGlow}`}>
          {statusIcon}
          <span>{status}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Circular Gauge */}
        <div className="md:col-span-5 flex flex-col items-center justify-center">
          <div className="relative w-36 h-36 flex items-center justify-center">
            {/* Animated Shockwave Halo */}
            <motion.div
              animate={{
                scale: [1, 1.08, 1],
                opacity: [0.2, 0.5, 0.2],
              }}
              transition={{
                duration: 3,
                repeat: Infinity,
                ease: 'easeInOut',
              }}
              className="absolute inset-0 rounded-full"
              style={{
                boxShadow: `0 0 25px ${strokeColor}40`,
                border: `1px solid ${strokeColor}30`,
              }}
            />

            <svg className="w-full h-full -rotate-90 p-2" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r={radius}
                className="stroke-slate-800/80 fill-none"
                strokeWidth="10"
              />
              <motion.circle
                cx="50"
                cy="50"
                r={radius}
                className="fill-none"
                stroke={strokeColor}
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={circumference}
                initial={{ strokeDashoffset: circumference }}
                animate={{ strokeDashoffset: strokeOffset }}
                transition={{ duration: 0.9, ease: 'easeOut' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <motion.span
                key={score}
                initial={{ scale: 0.7, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className="text-3xl font-extrabold font-mono text-white tracking-tight"
              >
                {score}
              </motion.span>
              <span className="text-[10px] uppercase font-mono text-slate-400 font-bold">/ 100 MAX</span>
            </div>
          </div>
          <span className="text-xs font-mono text-slate-400 mt-2 font-medium">Aggregated Threat Score</span>
        </div>

        {/* Verdict Details */}
        <div className="md:col-span-7 flex flex-col justify-center space-y-3">
          {isBlocked ? (
            <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-950/20 shadow-[0_0_20px_rgba(244,63,94,0.15)]">
              <div className="flex items-center gap-2 text-rose-400 font-bold text-sm uppercase tracking-wide">
                <Lock className="w-4 h-4" />
                <span>LLM Exposure: Prevented</span>
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                Critical adversarial signals detected. Request quarantined and prevented from reaching model context.
              </p>
            </div>
          ) : isSuspicious ? (
            <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/20">
              <div className="flex items-center gap-2 text-amber-300 font-bold text-sm uppercase tracking-wide">
                <AlertTriangle className="w-4 h-4" />
                <span>Sensitive Content Sanitized</span>
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                Moderate risk detected. Content was redacted before safe evaluation.
              </p>
            </div>
          ) : (
            <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-950/20">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm uppercase tracking-wide">
                <ShieldCheck className="w-4 h-4" />
                <span>Clean Request — Safe For LLM</span>
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                No active malicious patterns detected across rule scanners and antivirus layers.
              </p>
            </div>
          )}

          {/* Triggered Reasons */}
          {reasons && reasons.length > 0 && (
            <div className="pt-1">
              <span className="text-[11px] font-mono text-slate-400 uppercase font-semibold block mb-1.5">
                Triggered Threat Vectors:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {reasons.map((r, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30"
                  >
                    {r}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Breakdown Matrix */}
      {breakdown && Object.keys(breakdown).length > 0 && (
        <div className="mt-4 pt-3 border-t border-slate-800">
          <span className="text-[11px] font-mono uppercase text-slate-400 font-bold block mb-2">
            Active Risk Component Breakdown:
          </span>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {Object.entries(breakdown).map(([k, v]) => (
              <div key={k} className="p-2 rounded-lg bg-slate-800/40 border border-slate-800 flex justify-between items-center text-xs">
                <span className="font-mono text-slate-300 capitalize text-[11px] truncate">{k.replace('_', ' ')}</span>
                <span className="font-mono font-bold text-rose-400 text-xs">+{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
