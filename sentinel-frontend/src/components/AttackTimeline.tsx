import React from 'react';
import { Clock, CheckCircle2, ShieldAlert, AlertTriangle } from 'lucide-react';
import { ScanResult } from '../types/scan';

interface AttackTimelineProps {
  scanResult?: ScanResult;
}

export const AttackTimeline: React.FC<AttackTimelineProps> = ({ scanResult }) => {
  if (!scanResult) return null;

  const timestamp = new Date(scanResult.timestamp || Date.now()).toLocaleTimeString();
  const isBlocked = scanResult.status === 'BLOCKED';

  const timelineEvents = [
    { time: timestamp, event: 'INPUT RECEIVED', status: 'OK', desc: `Source context: ${scanResult.source_type}` },
    { time: timestamp, event: 'QUARANTINE ISOLATION', status: 'OK', desc: 'Payload secured in memory / isolated path' },
    {
      time: timestamp,
      event: 'SIGNATURE HASHING',
      status: 'OK',
      desc: scanResult.file_security?.file_hash ? `SHA-256: ${scanResult.file_security.file_hash.slice(0, 16)}...` : 'Text digest registered',
    },
    {
      time: timestamp,
      event: 'SECURITY DETECTORS EVALUATED',
      status: scanResult.reasons.length > 0 ? 'ALERT' : 'OK',
      desc: scanResult.reasons.length > 0 ? `Vectors: ${scanResult.reasons.join(', ')}` : 'Clean scan across all rules',
    },
    {
      time: timestamp,
      event: 'RISK SCORE COMPUTED',
      status: isBlocked ? 'CRITICAL' : 'OK',
      desc: `Aggregated score: ${scanResult.risk_score} / 100 (${scanResult.status})`,
    },
    {
      time: timestamp,
      event: 'SANITIZATION DISPATCH',
      status: 'OK',
      desc: `${scanResult.redactions_count} sensitive token(s) redacted`,
    },
    {
      time: timestamp,
      event: isBlocked ? 'GATEWAY ENFORCEMENT: BLOCKED' : 'GATEWAY ENFORCEMENT: ALLOWED',
      status: isBlocked ? 'BLOCKED' : 'SAFE',
      desc: isBlocked ? 'LLM Forwarding Aborted. Zero Exposure.' : 'Passed to model inference stream.',
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
            Chronological Security Audit Timeline
          </span>
        </div>
        <span className="text-xs font-mono text-slate-400">Scan ID: {scanResult.scan_id.slice(0, 8)}...</span>
      </div>

      <div className="relative border-l border-slate-800/80 ml-3 pl-5 space-y-4">
        {timelineEvents.map((item, idx) => {
          let dotColor = 'bg-slate-700 border-slate-900';
          let textColor = 'text-slate-300';

          if (item.status === 'OK' || item.status === 'SAFE') {
            dotColor = 'bg-emerald-400 border-emerald-950 shadow-[0_0_8px_#10b981]';
          } else if (item.status === 'ALERT') {
            dotColor = 'bg-amber-400 border-amber-950';
            textColor = 'text-amber-300';
          } else if (item.status === 'CRITICAL' || item.status === 'BLOCKED') {
            dotColor = 'bg-rose-500 border-rose-950 shadow-[0_0_10px_#ef4444]';
            textColor = 'text-rose-400';
          }

          return (
            <div key={idx} className="relative group">
              <span className={`absolute -left-[27px] top-1.5 w-3 h-3 rounded-full border-2 ${dotColor}`} />
              <div className="flex items-baseline justify-between">
                <span className={`text-xs font-mono font-bold uppercase tracking-wide ${textColor}`}>
                  {item.event}
                </span>
                <span className="text-[10px] font-mono text-slate-400">{item.time}</span>
              </div>
              <p className="text-[11px] font-mono text-slate-400 mt-0.5">{item.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
