import React from 'react';
import { ShieldCheck, Bug, Activity, Brain } from 'lucide-react';
import { SecurityHealthResponse } from '../types/security';

interface SecurityToolStatusProps {
  health?: SecurityHealthResponse | null;
}

export const SecurityToolStatus: React.FC<SecurityToolStatusProps> = ({ health }) => {
  const tools = health?.tools;

  const yara = tools?.yara;
  const clamav = tools?.clamav;
  const tshark = tools?.tshark;
  const jev = tools?.jev;

  const items = [
    {
      name: 'YARA Heuristics Engine',
      tool: 'yara',
      status: yara?.status || 'UNAVAILABLE',
      icon: <ShieldCheck className="w-5 h-5 text-cyan-400" />,
      detail: yara?.engine ? `Engine: ${yara.engine}` : 'Pattern Signature Matcher',
      color: yara?.status === 'ACTIVE' ? 'text-cyan-400 border-cyan-500/30' : 'text-slate-500 border-slate-800',
    },
    {
      name: 'ClamAV Antivirus Daemon',
      tool: 'clamav',
      status: clamav?.status || 'UNAVAILABLE',
      icon: <Bug className="w-5 h-5 text-emerald-400" />,
      detail: clamav?.binary ? `Binary: ${clamav.binary}` : 'Malware Scanner',
      color: clamav?.status === 'ACTIVE' ? 'text-emerald-400 border-emerald-500/30' : 'text-slate-500 border-slate-800',
    },
    {
      name: 'tshark Network Monitor',
      tool: 'tshark',
      status: tshark?.status || 'DISABLED',
      icon: <Activity className="w-5 h-5 text-purple-400" />,
      detail: 'Egress Traffic Telemetry (Disabled by default)',
      color: tshark?.status === 'ACTIVE' ? 'text-purple-400 border-purple-500/30' : 'text-slate-500 border-slate-800',
    },
    {
      name: 'Jev AI Classifier',
      tool: 'jev',
      status: jev?.status || 'UNAVAILABLE',
      icon: <Brain className="w-5 h-5 text-amber-400" />,
      detail: 'Modular Integration Layer (Pending API)',
      color: 'text-amber-400/80 border-slate-800',
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
          Linux Cybersecurity Stack Telemetry
        </span>
        <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> Linux Layer: {health?.linux_security_enabled ? 'ENABLED' : 'OFFLINE'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {items.map((it) => (
          <div key={it.tool} className={`p-3.5 rounded-xl border bg-slate-950/50 flex flex-col justify-between ${it.color}`}>
            <div className="flex items-start justify-between">
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">{it.icon}</div>
              <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border ${
                it.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                it.status === 'DISABLED' ? 'bg-slate-800 text-slate-400 border-slate-700' :
                'bg-slate-800/60 text-slate-400 border-slate-700'
              }`}>
                {it.status}
              </span>
            </div>
            <div className="mt-3">
              <h4 className="text-xs font-bold text-slate-200">{it.name}</h4>
              <p className="text-[10px] font-mono text-slate-400 mt-0.5 truncate">{it.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
