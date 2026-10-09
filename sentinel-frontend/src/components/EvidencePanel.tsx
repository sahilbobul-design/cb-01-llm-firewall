import React from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, Search } from 'lucide-react';
import { ScanThreats } from '../types/scan';

interface EvidencePanelProps {
  threats: ScanThreats;
  reasons: string[];
  reasonsBreakdown?: Record<string, number>;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({ threats, reasons }) => {
  const threatCards = [
    {
      id: 'prompt_injection',
      title: 'Prompt Injection',
      detected: threats.prompt_injection,
      severity: 'CRITICAL',
      detector: 'Rule Engine / Regex Heuristic',
      action: 'Override Neutralized',
      desc: 'Attempt to bypass model guardrails or disregard system instructions.',
    },
    {
      id: 'system_attack',
      title: 'System Prompt Attack',
      detected: threats.system_attack,
      severity: 'CRITICAL',
      detector: 'Instruction Integrity Scanner',
      action: 'Leak Blocked',
      desc: 'Attempt to extract or spoof system instructions via impersonation.',
    },
    {
      id: 'secret_detected',
      title: 'Secret / Token Exfiltration',
      detected: threats.secret_detected,
      severity: 'HIGH',
      detector: 'Credential Pattern Matcher',
      action: 'Masked / Redacted',
      desc: 'Sensitive API keys, OAuth tokens, or private credentials identified.',
    },
    {
      id: 'pii_detected',
      title: 'PII Leakage Exposure',
      detected: threats.pii_detected,
      severity: 'MEDIUM',
      detector: 'PII Regex Engine',
      action: 'Masked / Redacted',
      desc: 'SSN, email address, phone numbers, or confidential identity tokens.',
    },
    {
      id: 'yara_detected',
      title: 'YARA Pattern Match',
      detected: threats.yara_detected,
      severity: 'HIGH',
      detector: 'Linux YARA Engine',
      action: 'Quarantined & Flagged',
      desc: 'Adversarial shell patterns, evasion markers, or signature triggers.',
    },
    {
      id: 'clamav_infected',
      title: 'ClamAV Malware Detection',
      detected: threats.clamav_infected,
      severity: 'CRITICAL',
      detector: 'ClamAV Daemon / Scanner',
      action: 'Quarantined & Purged',
      desc: 'Known virus signature, malicious PDF object, or exploit fixture.',
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-cyan-400" />
          <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
            Threat Intelligence & Detector Evidence
          </span>
        </div>
        <span className="text-xs font-mono text-slate-400">Multi-Vector Analysis</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {threatCards.map((card) => {
          return (
            <div
              key={card.id}
              className={`p-3.5 rounded-xl border transition-all ${
                card.detected
                  ? 'border-rose-500/40 bg-rose-950/20 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
                  : 'border-slate-800/80 bg-slate-950/40 opacity-75'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <span className="text-xs font-bold font-mono text-slate-200">{card.title}</span>
                {card.detected ? (
                  <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" /> DETECTED
                  </span>
                ) : (
                  <span className="text-[10px] font-medium font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" /> CLEAN
                  </span>
                )}
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed mb-3">{card.desc}</p>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span>Detector: {card.detector}</span>
                {card.detected && <span className="font-bold text-rose-400">{card.action}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
