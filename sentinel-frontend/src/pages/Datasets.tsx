import React, { useEffect, useState } from 'react';
import { Database, Filter, RefreshCw, Play, ArrowRight, FileText } from 'lucide-react';
import { getDatasets, getRecords } from '../services/testApi';
import { DatasetItem, RecordItem } from '../types/scan';

interface DatasetsProps {
  onLoadRecordToTest: (record: RecordItem) => void;
}

export const Datasets: React.FC<DatasetsProps> = ({ onLoadRecordToTest }) => {
  const [datasets, setDatasets] = useState<DatasetItem[]>([]);
  const [activeDataset, setActiveDataset] = useState<DatasetItem | null>(null);
  const [records, setRecords] = useState<RecordItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [labelFilter, setLabelFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  const loadDatasets = async () => {
    setLoading(true);
    try {
      const data = await getDatasets();
      setDatasets(data);
      if (data.length > 0 && !activeDataset) {
        setActiveDataset(data[0]);
      }
    } catch (e) {
      console.warn('Failed to load datasets:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDatasets();
  }, []);

  useEffect(() => {
    if (activeDataset) {
      loadRecordsForDataset(activeDataset.id);
    }
  }, [activeDataset, labelFilter, sourceFilter]);

  const loadRecordsForDataset = async (datasetId: string) => {
    setLoading(true);
    try {
      const recs = await getRecords(datasetId, labelFilter || undefined, sourceFilter || undefined, 50);
      setRecords(Array.isArray(recs) ? recs : ((recs as any)?.records || []));
    } catch (e) {
      console.warn('Failed to load records:', e);
      setRecords([]);
    } finally {
      setLoading(false);
    }
  };

  const totalRecordsAcrossAll = datasets.reduce((sum, d) => sum + (d.record_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Database className="w-6 h-6 text-cyan-400" />
              DATASET & THREAT BENCHMARK INTELLIGENCE
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              Total Records: {totalRecordsAcrossAll}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Curated adversarial datasets including Microsoft BIPIA (Indirect Injections), Synthetic PDF Injections,
            and CIC-Evasive-PDFMal2022. Select any record to test directly against the Linux firewall.
          </p>
        </div>

        <button
          onClick={loadDatasets}
          disabled={loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs font-semibold border border-slate-700 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh Datasets
        </button>
      </div>

      {/* TWO COLUMN: DATASET SELECTOR & RECORDS VIEWER */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* DATASETS CARDS LIST */}
        <div className="lg:col-span-4 space-y-3">
          <span className="text-xs font-mono uppercase font-bold text-slate-400 block mb-2">
            Installed Benchmark Datasets:
          </span>
          {datasets.map((ds) => {
            const isActive = activeDataset?.id === ds.id;
            return (
              <div
                key={ds.id}
                onClick={() => setActiveDataset(ds)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isActive
                    ? 'border-cyan-400 bg-cyan-950/25 shadow-[0_0_20px_rgba(0,242,254,0.15)]'
                    : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <h4 className="text-sm font-bold text-slate-100 font-mono">{ds.name}</h4>
                  <span className="text-xs font-mono font-bold text-cyan-300 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20">
                    {ds.record_count} records
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-2">{ds.description}</p>
                <div className="text-[10px] font-mono text-slate-500 truncate">Source: {ds.source}</div>
              </div>
            );
          })}
        </div>

        {/* RECORDS TABLE */}
        <div className="lg:col-span-8 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-4">
            <div>
              <h3 className="text-sm font-bold font-mono text-slate-200">
                {activeDataset ? `${activeDataset.name} Records` : 'Dataset Records'}
              </h3>
              <span className="text-xs font-mono text-slate-400">{records.length} records retrieved</span>
            </div>

            <div className="flex items-center gap-2">
              <select
                value={labelFilter}
                onChange={(e) => setLabelFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-300"
              >
                <option value="">All Labels</option>
                <option value="benign">Benign Only</option>
                <option value="prompt_injection">Prompt Injection</option>
                <option value="malicious_file">Malicious File</option>
              </select>

              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-300"
              >
                <option value="">All Sources</option>
                <option value="email">Email</option>
                <option value="webpage">Webpage</option>
                <option value="pdf">PDF</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto max-h-[500px]">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                  <th className="py-2.5 px-3">Source</th>
                  <th className="py-2.5 px-3">Label</th>
                  <th className="py-2.5 px-3">Attack Type</th>
                  <th className="py-2.5 px-3">Snippet</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {records.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                      No records found matching current filters.
                    </td>
                  </tr>
                ) : (
                  records.map((r) => {
                    const isThreat = r.label !== 'benign';
                    return (
                      <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3 text-cyan-300 uppercase font-semibold">{r.source_type}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              isThreat
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}
                          >
                            {r.label}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{r.attack_type || 'None'}</td>
                        <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs" title={r.content}>
                          {r.content.slice(0, 75)}...
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() => onLoadRecordToTest(r)}
                            className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-bold text-[10px] uppercase border border-cyan-500/30 flex items-center gap-1 ml-auto"
                          >
                            <span>Test Record</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
