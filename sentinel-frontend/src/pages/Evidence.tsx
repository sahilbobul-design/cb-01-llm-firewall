import React, { useEffect, useState } from 'react';
import { ShieldAlert, Search, RefreshCw, FileText, CheckCircle2, AlertTriangle, Bug, Sparkles } from 'lucide-react';
import { getSecurityEvents, getToolResults, scanOutputFirewall } from '../services/scanApi';
import { SecurityEventItem } from '../types/security';
import { OutputFirewallResult } from '../types/scan';

export const Evidence: React.FC = () => {
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [toolResults, setToolResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');

  // Output Firewall interactive state
  const [outputTestText, setOutputTestText] = useState(
    'Here is the response. Internal API key: sk-live12345678901234567890123456789012 and SSN: 000-12-3456.'
  );
  const [firewallResult, setFirewallResult] = useState<OutputFirewallResult | null>(null);
  const [firewallLoading, setFirewallLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [evts, tools] = await Promise.all([getSecurityEvents(40), getToolResults(40)]);
      setEvents(evts);
      setToolResults(tools);
    } catch (e) {
      console.warn('Failed loading evidence data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunOutputFirewall = async () => {
    if (!outputTestText.trim()) return;
    setFirewallLoading(true);
    try {
      const res = await scanOutputFirewall(outputTestText);
      setFirewallResult(res);
    } catch (e: any) {
      alert(`Firewall scan error: ${e.message}`);
    } finally {
      setFirewallLoading(false);
    }
  };

  const filteredEvents = events.filter((ev) => {
    return !severityFilter || ev.severity === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Search className="w-6 h-6 text-cyan-400" />
              EVIDENCE & AUDIT LOGS
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              PostgreSQL Telemetry Tables
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Persistent forensic telemetry records from <code className="text-cyan-300">security_events</code> and{' '}
            <code className="text-cyan-300">tool_results</code>. Every detection event is immutably indexed.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs font-semibold border border-slate-700 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh Forensics
        </button>
      </div>

      {/* OUTPUT FIREWALL SIMULATION CARD */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
              Interactive Output Firewall Inspection (Post-LLM Response)
            </span>
          </div>
          <span className="text-xs font-mono text-slate-400">Leakage Redaction Test</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-start">
          <div>
            <label className="text-[11px] font-mono text-slate-400 uppercase font-bold block mb-1">
              Test LLM Output Text:
            </label>
            <textarea
              value={outputTestText}
              onChange={(e) => setOutputTestText(e.target.value)}
              rows={3}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/80 p-3 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-400"
            />
            <button
              onClick={handleRunOutputFirewall}
              disabled={firewallLoading}
              className="mt-2 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs uppercase font-mono transition-all disabled:opacity-50"
            >
              {firewallLoading ? 'Scanning...' : 'Test Output Firewall'}
            </button>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-950/80 font-mono text-xs min-h-[110px]">
            <span className="text-[10px] text-slate-400 uppercase block mb-1">Firewall Response & Redaction:</span>
            {firewallResult ? (
              <div className="space-y-2">
                <div className="flex items-center gap-3 text-[11px]">
                  <span className="text-slate-400">Action: <strong className="text-amber-300">{firewallResult.action}</strong></span>
                  <span className="text-slate-400">Redactions: <strong className="text-cyan-400">{firewallResult.redactions_count}</strong></span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-200 whitespace-pre-wrap">
                  {firewallResult.safe_output}
                </div>
              </div>
            ) : (
              <span className="text-slate-500 italic">Click "Test Output Firewall" to verify post-generation redaction.</span>
            )}
          </div>
        </div>
      </div>

      {/* SECURITY EVENTS TABLE */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span className="text-xs uppercase font-mono font-bold tracking-wider text-slate-400">
              Indexed Security Events ({filteredEvents.length})
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Filter Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-300"
            >
              <option value="">All</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Scan ID</th>
                <th className="py-2.5 px-3">Layer</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500 italic">
                    No security events logged yet. Execute a scan to populate forensic evidence.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2 px-3 text-slate-400 text-[11px]">
                      {new Date(ev.created_at).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 text-cyan-300 font-bold">{ev.scan_id.slice(0, 8)}...</td>
                    <td className="py-2 px-3 text-slate-300">{ev.layer}</td>
                    <td className="py-2 px-3 text-slate-200">{ev.event_type}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          ev.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : ev.severity === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-xs" title={ev.description}>
                      {ev.description}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
