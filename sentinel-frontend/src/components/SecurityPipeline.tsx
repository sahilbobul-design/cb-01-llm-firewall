import React from 'react';
import { motion } from 'framer-motion';
import {
  FileCheck,
  Hash,
  FileText,
  AlertTriangle,
  Lock,
  UserX,
  Brain,
  ShieldCheck,
  Bug,
  Activity,
  Gauge,
  Sparkles,
  ShieldAlert,
  HelpCircle,
  CheckCircle2,
  XCircle,
  MinusCircle,
  Loader2,
} from 'lucide-react';
import { PipelineStageNode, PipelineStageStatus } from '../types/test';

interface SecurityPipelineProps {
  stages: PipelineStageNode[];
  activeStageId?: string;
}

const STAGE_ICONS: Record<string, React.ReactNode> = {
  input: <FileText className="w-4 h-4" />,
  validation: <FileCheck className="w-4 h-4" />,
  hashing: <Hash className="w-4 h-4" />,
  extraction: <FileText className="w-4 h-4" />,
  prompt_injection: <AlertTriangle className="w-4 h-4" />,
  pii_detection: <UserX className="w-4 h-4" />,
  secret_detection: <Lock className="w-4 h-4" />,
  ai_classifier: <Brain className="w-4 h-4" />,
  yara: <ShieldCheck className="w-4 h-4" />,
  clamav: <Bug className="w-4 h-4" />,
  tshark: <Activity className="w-4 h-4" />,
  risk_engine: <Gauge className="w-4 h-4" />,
  sanitization: <Sparkles className="w-4 h-4" />,
  final_decision: <ShieldAlert className="w-4 h-4" />,
};

function getStatusBadge(status: PipelineStageStatus) {
  switch (status) {
    case 'RUNNING':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
          <Loader2 className="w-3 h-3 animate-spin" /> RUNNING
        </span>
      );
    case 'COMPLETED':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 className="w-3 h-3" /> OK
        </span>
      );
    case 'DETECTED':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
          <AlertTriangle className="w-3 h-3" /> DETECTED
        </span>
      );
    case 'BLOCKED':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 shadow-[0_0_10px_rgba(244,63,94,0.3)]">
          <XCircle className="w-3 h-3" /> BLOCKED
        </span>
      );
    case 'UNAVAILABLE':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
          <MinusCircle className="w-3 h-3" /> UNAVAILABLE
        </span>
      );
    case 'FAILED':
      return (
        <span className="flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700">
          <XCircle className="w-3 h-3" /> FAILED
        </span>
      );
    case 'PENDING':
    default:
      return (
        <span className="flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded bg-slate-800/60 text-slate-500 border border-slate-700/50">
          <HelpCircle className="w-3 h-3" /> PENDING
        </span>
      );
  }
}

export const SecurityPipeline: React.FC<SecurityPipelineProps> = ({ stages }) => {
  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f2fe]" />
          <h3 className="text-xs uppercase tracking-wider font-mono font-bold text-slate-400">
            Pipeline Orchestration Graph (14 Verified Defense Nodes)
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-500">Live Architecture Execution</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-7 gap-2.5">
        {stages.map((node, index) => {
          const isBlocked = node.status === 'BLOCKED' || (node.status === 'DETECTED' && node.id === 'final_decision');
          const isDetected = node.status === 'DETECTED';
          const isRunning = node.status === 'RUNNING';

          let borderClass = 'border-slate-800/80 bg-slate-900/40';
          if (isRunning) borderClass = 'border-cyan-500/60 bg-cyan-950/20 shadow-[0_0_15px_rgba(0,242,254,0.15)]';
          if (isDetected) borderClass = 'border-amber-500/60 bg-amber-950/20';
          if (isBlocked) borderClass = 'border-rose-500/60 bg-rose-950/25 shadow-[0_0_20px_rgba(244,63,94,0.2)]';

          return (
            <motion.div
              key={node.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              whileHover={{ scale: 1.05, y: -4, rotateZ: 0.5 }}
              transition={{ delay: index * 0.03, type: 'spring', stiffness: 300, damping: 20 }}
              className={`relative rounded-xl p-3 border transition-all duration-300 flex flex-col justify-between min-h-[104px] cursor-pointer ${borderClass}`}
            >
              <div className="flex items-start justify-between gap-1">
                <div className="p-1.5 rounded-lg bg-slate-800/80 text-cyan-300 border border-slate-700/60 shadow-inner">
                  {STAGE_ICONS[node.id] || <FileText className="w-4 h-4" />}
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-[9px] font-mono text-slate-500 font-bold">#{String(index + 1).padStart(2, '0')}</span>
                  {getStatusBadge(node.status)}
                </div>
              </div>

              <div className="mt-2">
                <div className="text-[11px] font-mono text-slate-200 font-bold uppercase truncate" title={node.name}>
                  {node.name}
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate" title={node.evidence || node.description}>
                  {node.evidence || node.description}
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};
