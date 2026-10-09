import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  LayoutDashboard,
  PlaySquare,
  FlaskConical,
  Search,
  Database,
  Radio,
  ExternalLink,
  Menu,
  X,
  Sparkles,
} from 'lucide-react';
import { Dashboard } from './pages/Dashboard';
import { FullSecurityTest } from './pages/FullSecurityTest';
import { ThreatStoryline } from './pages/ThreatStoryline';
import { SecurityLab } from './pages/SecurityLab';
import { Evidence } from './pages/Evidence';
import { Datasets } from './pages/Datasets';
import { getSystemHealth, getSecurityHealth } from './services/securityApi';
import { RecordItem } from './types/scan';

type NavigationTab = 'dashboard' | 'full-test' | 'story' | 'security-lab' | 'evidence' | 'datasets';

export function App() {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('full-test'); // Default to HERO SCREEN
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // System Statuses
  const [apiOnline, setApiOnline] = useState(false);
  const [dbOnline, setDbOnline] = useState(false);
  const [engineOnline, setEngineOnline] = useState(false);

  useEffect(() => {
    async function checkStatus() {
      try {
        const sys = await getSystemHealth();
        setApiOnline(sys.status === 'healthy');
        setDbOnline(sys.database === 'connected');
      } catch {
        setApiOnline(false);
        setDbOnline(false);
      }

      try {
        const sec = await getSecurityHealth();
        setEngineOnline(sec.gateway_status === 'ONLINE');
      } catch {
        setEngineOnline(false);
      }
    }

    checkStatus();
    const interval = setInterval(checkStatus, 12000);
    return () => clearInterval(interval);
  }, []);

  const [selectedRecordToTest, setSelectedRecordToTest] = useState<RecordItem | null>(null);

  const handleLoadRecordToTest = (record: RecordItem) => {
    setSelectedRecordToTest(record);
    setCurrentTab('full-test');
  };

  const navItems = [
    { id: 'dashboard', label: 'COMMAND CENTER', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'full-test', label: 'FULL SECURITY TEST', icon: <PlaySquare className="w-4 h-4" /> },
    { id: 'story', label: '3D ATTACK STORY', icon: <Sparkles className="w-4 h-4 text-cyan-300 animate-pulse" />, isNew: true },
    { id: 'security-lab', label: 'SECURITY LAB (18 TCs)', icon: <FlaskConical className="w-4 h-4" /> },
    { id: 'evidence', label: 'EVIDENCE & AUDIT', icon: <Search className="w-4 h-4" /> },
    { id: 'datasets', label: 'BENCHMARK DATASETS', icon: <Database className="w-4 h-4" /> },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#07090e] text-slate-100 font-sans">
      {/* SIDEBAR NAVIGATION */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 border-r border-slate-800 bg-[#0a0e17]/95 backdrop-blur-2xl flex flex-col justify-between transition-transform duration-300 md:static md:translate-x-0 ${
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div>
          {/* BRAND */}
          <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400/20 to-purple-600/30 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(0,242,254,0.25)]">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-base font-extrabold tracking-tight bg-gradient-to-r from-white to-cyan-300 bg-clip-text text-transparent">
                  SENTINEL AI
                </h2>
                <span className="text-[10px] font-mono font-semibold tracking-wider text-slate-500 uppercase block">
                  LLM Firewall & Gateway
                </span>
              </div>
            </div>
            <button
              onClick={() => setMobileMenuOpen(false)}
              className="md:hidden text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* NAV LINKS */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentTab(item.id as NavigationTab);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl font-mono text-xs font-bold tracking-wider transition-all text-left ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_15px_rgba(0,242,254,0.15)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <span className={isActive ? 'text-cyan-400' : 'text-slate-500'}>{item.icon}</span>
                  <span>{item.label}</span>
                  {item.isNew && (
                    <span className="ml-auto px-1.5 py-0.5 rounded text-[9px] font-mono font-black bg-cyan-400 text-black shadow-[0_0_8px_rgba(0,242,254,0.6)]">
                      3D
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* BOTTOM: SYSTEM STATUS & SOC BADGE */}
        <div className="p-4 border-t border-slate-800/80 space-y-3 bg-slate-950/40">
          <div>
            <span className="text-[10px] font-mono uppercase text-slate-400 font-bold tracking-wider block mb-2">
              System Telemetry:
            </span>
            <div className="space-y-1.5 text-[11px] font-mono">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">API Gateway</span>
                <span className="flex items-center gap-1 font-bold">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      apiOnline ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-rose-500'
                    }`}
                  />
                  <span className={apiOnline ? 'text-emerald-400' : 'text-rose-400'}>
                    {apiOnline ? 'ONLINE' : 'OFFLINE'}
                  </span>
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">PostgreSQL / DB</span>
                <span className="flex items-center gap-1 font-bold">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      dbOnline ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-rose-500'
                    }`}
                  />
                  <span className={dbOnline ? 'text-emerald-400' : 'text-rose-400'}>
                    {dbOnline ? 'CONNECTED' : 'DISCONNECTED'}
                  </span>
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-400">Security Engine</span>
                <span className="flex items-center gap-1 font-bold">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      engineOnline ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-amber-400'
                    }`}
                  />
                  <span className={engineOnline ? 'text-emerald-400' : 'text-amber-400'}>
                    {engineOnline ? 'ACTIVE' : 'DEGRADED'}
                  </span>
                </span>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/60 text-center">
            <span className="text-[10px] font-mono text-slate-400 block font-bold">SENTINEL AI</span>
            <span className="text-[9px] font-mono text-slate-400 block">AI SECURITY GATEWAY</span>
          </div>
        </div>
      </aside>

      {/* MAIN VIEW CONTENT CONTAINER */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* TOP MOBILE BAR */}
        <header className="md:hidden flex items-center justify-between p-4 border-b border-slate-800 bg-[#0a0e17]">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="font-extrabold text-sm">SENTINEL AI</span>
          </div>
          <button
            onClick={() => setMobileMenuOpen(true)}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-300"
          >
            <Menu className="w-5 h-5" />
          </button>
        </header>

        {/* SCROLLABLE VIEW AREA */}
        <main className="flex-1 overflow-y-auto p-4 md:p-8">
          <div className="max-w-7xl mx-auto pb-12">
            <AnimatePresence mode="wait">
              <motion.div
                key={currentTab}
                initial={{ opacity: 0, y: 16, filter: 'blur(6px)' }}
                animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
                exit={{ opacity: 0, y: -16, filter: 'blur(6px)' }}
                transition={{ duration: 0.28, ease: 'easeOut' }}
              >
                {currentTab === 'dashboard' && (
                  <Dashboard onNavigateToFullTest={() => setCurrentTab('full-test')} />
                )}
                {currentTab === 'full-test' && (
                  <FullSecurityTest
                    initialPrompt={selectedRecordToTest?.content}
                    initialSourceType={selectedRecordToTest?.source_type}
                  />
                )}
                {currentTab === 'story' && <ThreatStoryline />}
                {currentTab === 'security-lab' && <SecurityLab />}
                {currentTab === 'evidence' && <Evidence />}
                {currentTab === 'datasets' && <Datasets onLoadRecordToTest={handleLoadRecordToTest} />}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}
export default App;
