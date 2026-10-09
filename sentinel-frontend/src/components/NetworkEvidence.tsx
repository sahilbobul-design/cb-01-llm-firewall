import React from 'react';
import { Activity, ShieldOff, Info } from 'lucide-react';
import { ToolResultDetail } from '../types/scan';

interface NetworkEvidenceProps {
  tsharkResult?: ToolResultDetail;
}

export const NetworkEvidence: React.FC<NetworkEvidenceProps> = ({ tsharkResult }) => {
  const isEnabled = tsharkResult?.status === 'ACTIVE' || tsharkResult?.status === 'COMPLETED';

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-purple-400" />
          <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
            Network Telemetry & Traffic Monitoring
          </span>
        </div>
        <span
          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
            isEnabled
              ? 'bg-purple-500/10 text-purple-300 border-purple-500/20'
              : 'bg-slate-800 text-slate-500 border-slate-700'
          }`}
        >
          {isEnabled ? 'MONITORING ACTIVE' : 'DISABLED (DEFAULT)'}
        </span>
      </div>

      {isEnabled ? (
        <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-300">
          <p>Controlled packet analysis completed on allowlisted interface.</p>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-800/80 flex items-start gap-3">
          <Info className="w-4 h-4 text-slate-500 mt-0.5 flex-shrink-0" />
          <div className="text-xs text-slate-400 leading-relaxed">
            <span className="text-slate-300 font-semibold font-mono block mb-1">
              Architecture Isolation Principle:
            </span>
            Network monitoring via <code className="text-purple-300">tshark</code> monitors external network interfaces (eth0)
            and is disabled by default (<code className="text-slate-400">NETWORK_MONITOR_ENABLED=false</code>). Per security guidelines,
            network scanners are never run directly against document files or text.
          </div>
        </div>
      )}
    </div>
  );
};
