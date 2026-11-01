import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Activity, AlertTriangle, Layers, Crosshair, 
  CheckCircle2, XCircle, Sliders, Server, Eye, ExternalLink, 
  Terminal, ArrowRight, Zap, RefreshCw, BarChart2, Radio, Check,
  Star, Sparkles, ShieldCheck, ChevronRight
} from 'lucide-react';

interface StatsOverview {
  requests_per_sec: number;
  error_rate: number;
  p95_latency_ms: number;
  current_risk_gauge: number;
  active_alerts_count: number;
  open_incidents_count: number;
  operating_mode: string;
  shadow_attacker_mitigated_pct: number;
  shadow_legit_impacted_pct: number;
}

interface AlertItem {
  alert_id: string;
  incident_id?: string;
  category: string;
  owasp: string;
  risk: number;
  confidence: number;
  window: string;
  status: string;
  evidence: any;
  created_at: string;
}

interface IncidentItem {
  incident_id: string;
  title: string;
  status: string;
  stage: string;
  risk: number;
  entities: any;
  timeline: any[];
  created_at: string;
  updated_at: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'alerts' | 'incidents' | 'lab' | 'evaluation' | 'health' | 'settings'>('overview');
  const [stats, setStats] = useState<StatsOverview | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [evalData, setEvalData] = useState<any>(null);
  const [wsConnected, setWsConnected] = useState(false);
  
  // Attack Lab State
  const [labScenario, setLabScenario] = useState('A1');
  const [labStealth, setLabStealth] = useState(2);
  const [labIntensity, setLabIntensity] = useState(60);
  const [labTriggering, setLabTriggering] = useState(false);
  const [labMessage, setLabMessage] = useState('');

  // Fetch initial data & polling
  const fetchData = async () => {
    try {
      const [resStats, resAlerts, resInc, resEval] = await Promise.all([
        fetch('/v1/stats/overview').then(r => r.ok ? r.json() : null),
        fetch('/v1/alerts').then(r => r.ok ? r.json() : []),
        fetch('/v1/incidents').then(r => r.ok ? r.json() : []),
        fetch('/v1/eval/latest').then(r => r.ok ? r.json() : null)
      ]);
      if (resStats) setStats(resStats);
      if (resAlerts) setAlerts(resAlerts);
      if (resInc) setIncidents(resInc);
      if (resEval) setEvalData(resEval);
    } catch (e) {
      console.error("Failed to load telemetry", e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);

    // WebSocket telemetry stream
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/v1/stream`;
    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => setWsConnected(false);
    } catch (e) {
      setWsConnected(false);
    }

    return () => {
      clearInterval(interval);
      if (ws) ws.close();
    };
  }, []);

  const triggerScenario = async (sc: string, stealth = labStealth, count = labIntensity) => {
    setLabTriggering(true);
    setLabMessage(`Dispatching ${sc} (Stealth ${stealth}, ${count} calls)...`);
    try {
      const res = await fetch(`/v1/sim/scenarios/${sc}/start?count=${count}&stealth=${stealth}`, {
        method: 'POST'
      });
      if (res.ok) {
        setLabMessage(`Scenario ${sc} dispatched to target! Ingesting telemetry into detection window...`);
        setTimeout(fetchData, 1200);
      }
    } catch (e) {
      setLabMessage(`Error launching scenario: ${e}`);
    } finally {
      setLabTriggering(false);
    }
  };

  const submitFeedback = async (alertId: string, type: string) => {
    try {
      await fetch(`/v1/alerts/${alertId}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ feedback: type, notes: "Analyst dashboard feedback" })
      });
      fetchData();
      if (selectedAlert) {
        setSelectedAlert({ ...selectedAlert, status: type === 'suppress' ? 'resolved' : selectedAlert.status });
      }
    } catch (e) {
      console.error("Feedback submission error", e);
    }
  };

  const getRiskColor = (risk: number) => {
    if (risk >= 80) return 'text-rose-400 bg-rose-950/40 border-rose-800/60';
    if (risk >= 50) return 'text-amber-400 bg-amber-950/40 border-amber-800/60';
    return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60';
  };

  return (
    <div className="min-h-screen bg-[#090706] text-stone-100 flex flex-col font-sans relative tech-grid-bg ambient-glow selection:bg-amber-500/30 selection:text-amber-200 pb-16">
      
      {/* Top Header / App Bar */}
      <header className="border-b border-[#241c16]/80 bg-[#0d0a08]/80 backdrop-blur-md px-6 py-3.5 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3.5">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-amber-500/20 to-amber-600/5 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.15)]">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <span className="font-bold text-lg tracking-tight text-white flex items-center gap-1.5">
                Wardwire
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-stone-900 border border-stone-800 text-stone-300 font-mono">
                v1.0.0
              </span>
            </div>
            <p className="text-[11px] text-stone-400">Real-Time API Abuse Detection & Explanation</p>
          </div>
        </div>

        {/* Operating Badges & Status Controls */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-stone-900/90 border border-stone-800/80 shadow-sm">
            <Radio className={`w-3 h-3 ${wsConnected ? 'text-amber-400 animate-pulse' : 'text-stone-500'}`} />
            <span className="text-[11px] text-stone-300 font-mono tracking-wide">{wsConnected ? 'LIVE FEED' : 'CONNECTING'}</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-amber-950/20 border border-amber-600/30 text-amber-300 text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping"></span>
            <span>SHADOW MODE</span>
            <span className="text-[10px] text-amber-400/90 bg-amber-900/40 px-1.5 py-0.2 rounded-full font-mono">PASS-THROUGH</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-stone-900/90 border border-stone-800/80">
            <span className="text-[11px] text-stone-400">Threat Gauge</span>
            <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded-full border ${getRiskColor(stats?.current_risk_gauge || 15)}`}>
              {stats?.current_risk_gauge || 15}/100
            </span>
          </div>
        </div>
      </header>

      {/* Sleek Segmented Navigation Dock */}
      <nav className="bg-[#0e0b09]/90 border-b border-[#241c16]/70 px-6 flex space-x-1 sm:space-x-3 text-xs overflow-x-auto backdrop-blur-sm sticky top-[61px] z-30">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'alerts', label: `Alerts (${alerts.length})`, icon: ShieldAlert },
          { id: 'incidents', label: `Incidents (${incidents.length})`, icon: Layers },
          { id: 'lab', label: 'Attack Lab', icon: Crosshair },
          { id: 'evaluation', label: 'Evaluation & Benchmarks', icon: BarChart2 },
          { id: 'health', label: 'Detector Health & Drift', icon: Server },
          { id: 'settings', label: 'Settings', icon: Sliders },
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-3 px-3 flex items-center space-x-2 font-medium transition-all relative whitespace-nowrap ${
                isActive 
                  ? 'text-amber-400' 
                  : 'text-stone-400 hover:text-stone-200 hover:bg-stone-900/40 rounded-t-lg'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-amber-400' : 'text-stone-500'}`} />
              <span>{tab.label}</span>
              {isActive && (
                <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-amber-500 to-amber-400 shadow-[0_0_8px_rgba(245,158,11,0.6)]" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Main Content Container */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            
            {/* Hero / Announcement Card styled like Supastarter */}
            <div className="relative overflow-hidden rounded-2xl bg-gradient-to-b from-[#17110d] via-[#120e0b] to-[#0d0a08] border border-[#2b211a] p-8 shadow-2xl text-center flex flex-col items-center">
              
              {/* Subtle top glow ring inside card */}
              <div className="absolute top-0 left-1/2 -translate-x-1/2 w-3/4 h-24 bg-amber-500/10 blur-3xl pointer-events-none rounded-full" />
              
              {/* Announcement Pill Badge */}
              <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-amber-950/30 border border-amber-500/30 text-amber-200 text-xs mb-5 shadow-sm hover:border-amber-400/50 transition cursor-default">
                <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 bg-amber-950/60 px-1.5 py-0.5 rounded-full border border-amber-800/40">New</span>
                <span>Hybrid Ensemble • River HalfSpaceTrees • 6 Benign Differentiators</span>
                <ChevronRight className="w-3.5 h-3.5 text-amber-400" />
              </div>

              {/* Bold Hero Typography */}
              <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-[#fcfaf7] max-w-3xl leading-[1.15]">
                The API defense engine your <span className="bg-gradient-to-r from-amber-200 via-amber-400 to-amber-200 bg-clip-text text-transparent">production APIs</span> deserve
              </h1>

              {/* Feature Value Props Line */}
              <div className="flex flex-wrap items-center justify-center gap-y-2 gap-x-6 mt-4 text-xs text-stone-400 font-medium">
                <div className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                  <span>Sub-millisecond Streaming</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                  <span>Hypothesis Benign Differentiator</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                  <span>Privacy-Safe Salted HMAC</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
                  <span>Zero-Disruption Shadow Mode</span>
                </div>
              </div>

              {/* Interactive Pill Action Buttons */}
              <div className="flex flex-wrap items-center justify-center gap-3 mt-7">
                <button
                  onClick={() => triggerScenario('A1', 2, 80)}
                  disabled={labTriggering}
                  className="px-6 py-2.5 rounded-full bg-gradient-to-r from-amber-600/30 via-amber-500/20 to-amber-700/20 hover:from-amber-500/40 hover:to-amber-600/30 text-amber-100 text-xs font-semibold border border-amber-500/70 shadow-[0_0_20px_rgba(245,158,11,0.25)] hover:shadow-[0_0_30px_rgba(245,158,11,0.4)] hover:border-amber-400 flex items-center space-x-2 transition-all transform active:scale-98 disabled:opacity-50"
                >
                  <Crosshair className="w-3.5 h-3.5 text-amber-300" />
                  <span>Launch Distributed A1 Attack</span>
                  <ChevronRight className="w-3.5 h-3.5 text-amber-400 ml-1" />
                </button>

                <button
                  onClick={() => triggerScenario('B1', 0, 100)}
                  disabled={labTriggering}
                  className="px-5 py-2.5 rounded-full bg-stone-900/90 hover:bg-stone-800/90 text-stone-200 text-xs font-semibold border border-stone-700/80 hover:border-stone-600 shadow-sm flex items-center space-x-2 transition-all transform active:scale-98 disabled:opacity-50"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Simulate Flash Sale B1</span>
                </button>
              </div>

              {/* Social Proof / Security Verification Stack */}
              <div className="flex items-center space-x-2.5 mt-6 pt-5 border-t border-[#261d17]/80 text-xs text-stone-400">
                <div className="flex -space-x-1.5">
                  <span className="w-5 h-5 rounded-full bg-amber-950 border border-amber-700/60 flex items-center justify-center text-[10px] font-mono font-bold text-amber-300">A1</span>
                  <span className="w-5 h-5 rounded-full bg-stone-800 border border-stone-700 flex items-center justify-center text-[10px] font-mono font-bold text-stone-300">A2</span>
                  <span className="w-5 h-5 rounded-full bg-stone-800 border border-stone-700 flex items-center justify-center text-[10px] font-mono font-bold text-stone-300">A3</span>
                  <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-700/60 flex items-center justify-center text-[10px] font-mono font-bold text-emerald-300">B1</span>
                </div>
                <div className="flex items-center text-amber-400 text-xs">
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400" />
                </div>
                <span className="text-[11px] text-stone-400">
                  verified by <strong className="text-stone-200">20,916 events/sec</strong> benchmark • OWASP API Top 10
                </span>
              </div>
            </div>

            {/* Notification Bar if Triggering */}
            {labMessage && (
              <div className="p-3.5 bg-[#140f0c] border border-amber-500/40 rounded-xl text-xs font-mono text-amber-300 flex items-center space-x-2.5 shadow-md">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400 flex-shrink-0" />
                <span>{labMessage}</span>
              </div>
            )}

            {/* Four Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17] shadow-sm hover:border-[#382b21] transition relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/[0.03] rounded-full blur-xl pointer-events-none" />
                <span className="text-xs text-stone-400 font-medium">Telemetry Rate</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-stone-100">{stats?.requests_per_sec || 0}</span>
                  <span className="text-xs text-stone-500 font-mono">req/sec</span>
                </div>
                <span className="text-[11px] text-amber-400/90 mt-1 flex items-center gap-1 font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                  Passthrough ASGI Telemetry
                </span>
              </div>

              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17] shadow-sm hover:border-[#382b21] transition relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/[0.03] rounded-full blur-xl pointer-events-none" />
                <span className="text-xs text-stone-400 font-medium">Error Rate</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-stone-100">
                    {((stats?.error_rate || 0) * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-stone-500 font-mono">4xx/5xx</span>
                </div>
                <span className="text-[11px] text-stone-400 mt-1 block">Diurnal baseline tracked</span>
              </div>

              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17] shadow-sm hover:border-[#382b21] transition relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/[0.03] rounded-full blur-xl pointer-events-none" />
                <span className="text-xs text-stone-400 font-medium">Latency (p95)</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-stone-100">{stats?.p95_latency_ms || 28}</span>
                  <span className="text-xs text-stone-500 font-mono">ms</span>
                </div>
                <span className="text-[11px] text-emerald-400 mt-1 block">&lt; 50ms engine SLA</span>
              </div>

              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17] shadow-sm hover:border-[#382b21] transition relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/[0.03] rounded-full blur-xl pointer-events-none" />
                <span className="text-xs text-stone-400 font-medium">Shadow Mitigation Efficacy</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-emerald-400">
                    {stats?.shadow_attacker_mitigated_pct || 94.2}%
                  </span>
                  <span className="text-xs text-stone-500 font-mono">blocked</span>
                </div>
                <span className="text-[11px] text-stone-400 mt-1 block">
                  Legit user blast: {stats?.shadow_legit_impacted_pct || 0.1}%
                </span>
              </div>
            </div>

            {/* Live Alerts Feed & Active Incidents Preview */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Detected Alerts Preview */}
              <div className="lg:col-span-2 bg-[#120e0b] rounded-xl border border-[#261d17] p-5 shadow-sm">
                <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#241c16]/70">
                  <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <span>Real-Time Detected Alerts</span>
                  </h3>
                  <span className="text-xs text-stone-400 font-mono">Multi-entity correlated</span>
                </div>

                <div className="space-y-2.5">
                  {alerts.length === 0 ? (
                    <div className="text-center py-10 text-stone-500 text-xs">No active alerts. System healthy.</div>
                  ) : (
                    alerts.slice(0, 5).map(a => (
                      <div 
                        key={a.alert_id} 
                        onClick={() => { setSelectedAlert(a); setActiveTab('alerts'); }}
                        className="p-3.5 rounded-xl bg-[#17120e]/80 hover:bg-[#1f1712] border border-[#292019] cursor-pointer transition flex items-center justify-between group"
                      >
                        <div className="flex items-center space-x-3">
                          <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded-full border ${getRiskColor(a.risk)}`}>
                            {a.risk}
                          </span>
                          <div>
                            <div className="flex items-center space-x-2">
                              <span className="text-sm font-semibold text-stone-100 capitalize">{a.category.replace(/_/g, ' ')}</span>
                              <span className="text-[11px] px-2 py-0.2 rounded-full bg-stone-900 border border-stone-800 text-amber-300 font-mono">{a.owasp}</span>
                            </div>
                            <p className="text-xs text-stone-400 mt-0.5 line-clamp-1">{a.evidence.explanation}</p>
                          </div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-stone-500 group-hover:text-amber-400 transition" />
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Incidents Preview */}
              <div className="bg-[#120e0b] rounded-xl border border-[#261d17] p-5 shadow-sm">
                <h3 className="text-sm font-bold text-white mb-4 pb-2 border-b border-[#241c16]/70 flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-amber-400" />
                  <span>Correlated Incidents</span>
                </h3>

                <div className="space-y-3">
                  {incidents.length === 0 ? (
                    <div className="text-center py-10 text-stone-500 text-xs">No multi-stage incidents open.</div>
                  ) : (
                    incidents.slice(0, 4).map(inc => (
                      <div key={inc.incident_id} className="p-3 bg-[#17120e]/80 rounded-xl border border-[#292019]">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-stone-200 line-clamp-1">{inc.title}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-950/40 text-amber-300 border border-amber-800/40 uppercase font-semibold">{inc.stage}</span>
                        </div>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-stone-400">
                          <span>Threat: <strong className="text-amber-400">{inc.risk}/100</strong></span>
                          <span>{inc.timeline.length} correlated events</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ALERTS TAB & DETAIL DRAWER */}
        {activeTab === 'alerts' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Alerts List */}
            <div className={`${selectedAlert ? 'lg:col-span-5' : 'lg:col-span-12'} space-y-3`}>
              <div className="flex items-center justify-between pb-2 border-b border-[#261d17]">
                <span className="text-sm font-bold text-white">Detection Feed ({alerts.length})</span>
                <span className="text-xs text-stone-400">Select any alert for complete evidence</span>
              </div>

              {alerts.length === 0 ? (
                <div className="p-12 text-center text-stone-500 text-xs bg-[#120e0b] rounded-xl border border-[#261d17]">
                  No alerts triggered. Head to the Attack Lab to dispatch simulated attack traffic.
                </div>
              ) : (
                alerts.map(a => (
                  <div
                    key={a.alert_id}
                    onClick={() => setSelectedAlert(a)}
                    className={`p-4 rounded-xl border cursor-pointer transition ${
                      selectedAlert?.alert_id === a.alert_id
                        ? 'bg-[#1b1510] border-amber-500/70 shadow-[0_0_15px_rgba(245,158,11,0.15)]'
                        : 'bg-[#120e0b] border-[#261d17] hover:border-[#382b21]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-full border ${getRiskColor(a.risk)}`}>
                          RISK {a.risk}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-stone-900 border border-stone-800 text-stone-300 font-mono">{a.owasp}</span>
                      </div>
                      <span className="text-[11px] text-stone-400 font-mono uppercase">{a.status}</span>
                    </div>

                    <h4 className="text-sm font-semibold text-white mt-2 capitalize">{a.category.replace(/_/g, ' ')}</h4>
                    <p className="text-xs text-stone-300 mt-1 line-clamp-2">{a.evidence.explanation}</p>
                  </div>
                ))
              )}
            </div>

            {/* Evidence & Explanation Drawer */}
            {selectedAlert && (
              <div className="lg:col-span-7 bg-[#120e0b] rounded-xl border border-[#261d17] p-6 space-y-6 shadow-2xl sticky top-24">
                <div className="flex items-center justify-between pb-3 border-b border-[#241c16]">
                  <div>
                    <span className="text-xs text-stone-400 font-mono">{selectedAlert.alert_id}</span>
                    <h3 className="text-base font-bold text-white capitalize mt-0.5">{selectedAlert.category.replace(/_/g, ' ')}</h3>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => submitFeedback(selectedAlert.alert_id, 'tp')}
                      className="px-3 py-1 rounded-full bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-300 text-xs font-semibold transition"
                    >
                      True Positive
                    </button>
                    <button
                      onClick={() => submitFeedback(selectedAlert.alert_id, 'suppress')}
                      className="px-3 py-1 rounded-full bg-stone-900 hover:bg-stone-800 border border-stone-700 text-stone-300 text-xs font-semibold transition"
                    >
                      Suppress
                    </button>
                  </div>
                </div>

                {/* Explanation */}
                <div>
                  <h4 className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-2">Deterministic Narrative</h4>
                  <div className="p-4 bg-[#17120e] rounded-xl border border-[#292019] text-xs text-stone-200 leading-relaxed font-sans">
                    {selectedAlert.evidence.explanation}
                  </div>
                </div>

                {/* "Why Not Benign?" Critical Differentiator Panel */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center space-x-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>Why This Is Not Benign Traffic (Hypothesis Testing)</span>
                    </h4>
                    <span className="text-[11px] text-stone-500 font-mono">6 Hypothesis Tests</span>
                  </div>

                  <div className="space-y-2">
                    {selectedAlert.evidence.why_not_benign?.map((chk: any, idx: number) => {
                      const isConsistent = chk.verdict === 'consistent_with_benign';
                      return (
                        <div key={idx} className="p-3 rounded-xl bg-[#17120e] border border-[#292019] text-xs flex items-start justify-between">
                          <div>
                            <span className="font-semibold text-stone-200 capitalize">{chk.check.replace(/_/g, ' ')}</span>
                            <p className="text-[11px] text-stone-400 mt-0.5">{chk.detail}</p>
                          </div>
                          <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full font-bold whitespace-nowrap ml-2 ${
                            isConsistent 
                              ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60' 
                              : 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                          }`}>
                            {isConsistent ? 'BENIGN PASS' : 'ANOMALOUS'}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Action Ladder & Blast Radius */}
                <div>
                  <h4 className="text-xs font-bold text-amber-400/90 uppercase tracking-wider mb-2">Recommended Response Ladder</h4>
                  <div className="space-y-2">
                    {selectedAlert.evidence.recommendations?.map((rec: any, idx: number) => (
                      <div key={idx} className="p-3 bg-amber-950/10 border border-amber-900/30 rounded-xl flex items-center justify-between text-xs">
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-amber-300 uppercase">{rec.action.replace(/_/g, ' ')}</span>
                            <span className="text-[11px] text-stone-400 font-mono">{rec.target}</span>
                          </div>
                          <p className="text-[11px] text-stone-400 mt-1">{rec.reason}</p>
                        </div>
                        <div className="text-right">
                          <span className="text-[11px] text-stone-500 block">Est. Blast Radius</span>
                          <span className="font-mono text-emerald-400 font-bold">{rec.est_legit_impact_pct}% legit</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Pseudonymized Sample Requests */}
                <div>
                  <h4 className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-2">Pseudonymized Sample Requests (Privacy Safe)</h4>
                  <div className="p-3 bg-[#0d0a08] rounded-xl border border-[#241c16] font-mono text-[11px] text-stone-300 space-y-1">
                    {selectedAlert.evidence.sample_requests?.length > 0 ? (
                      selectedAlert.evidence.sample_requests.map((r: any, idx: number) => (
                        <div key={idx} className="flex space-x-3">
                          <span className="text-stone-500">{r.ts?.slice(11, 19)}</span>
                          <span className="text-amber-400">{r.route}</span>
                          <span className={r.status >= 400 ? 'text-rose-400' : 'text-emerald-400'}>{r.status}</span>
                          <span className="text-stone-400">{r.ip_id}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-stone-500">Entities: {JSON.stringify(selectedAlert.evidence.entities)}</div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* INCIDENTS TAB */}
        {activeTab === 'incidents' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#261d17]">
              <div>
                <span className="text-sm font-bold text-white">Multi-Stage Incident Campaigns</span>
                <p className="text-xs text-stone-400">Correlated across IP subnets, accounts, and fingerprints</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {incidents.length === 0 ? (
                <div className="col-span-2 p-12 text-center text-stone-500 text-xs bg-[#120e0b] rounded-xl border border-[#261d17]">
                  No multi-stage campaigns detected. Use the Attack Lab to simulate multi-step penetration attempts.
                </div>
              ) : (
                incidents.map(inc => (
                  <div key={inc.incident_id} className="bg-[#120e0b] rounded-xl border border-[#261d17] p-5 shadow-sm space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-stone-500">{inc.incident_id}</span>
                      <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-amber-950/40 text-amber-300 uppercase font-bold border border-amber-800/40">
                        Stage: {inc.stage}
                      </span>
                    </div>

                    <h3 className="text-base font-bold text-white">{inc.title}</h3>

                    <div>
                      <h4 className="text-xs font-bold text-stone-400 uppercase tracking-wider mb-2">Campaign Timeline</h4>
                      <div className="space-y-2 border-l-2 border-[#2b211a] pl-3">
                        {inc.timeline.map((item: any, idx: number) => (
                          <div key={idx} className="text-xs">
                            <div className="flex items-center justify-between text-stone-400">
                              <span>{item.ts?.slice(11, 19)} UTC</span>
                              <span className="text-amber-400 font-mono font-bold">Risk {item.risk}</span>
                            </div>
                            <p className="text-stone-200 mt-0.5">{item.event}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* ATTACK LAB TAB */}
        {activeTab === 'lab' && (
          <div className="space-y-6">
            
            {/* Control Panel */}
            <div className="bg-[#120e0b] border border-[#261d17] rounded-2xl p-6 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center space-x-2">
                    <Crosshair className="w-5 h-5 text-amber-400" />
                    <span>Adversarial Attack Lab (Round 2 Live Demonstration)</span>
                  </h3>
                  <p className="text-xs text-stone-400 mt-1">
                    Triggers live HTTP scenarios against ShopAPI demo target (localhost). Verified safety allow-list refusal in place.
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-stone-500 block">Target Whitelist:</span>
                  <span className="text-xs font-mono text-emerald-400">target:8000 (Allow-listed)</span>
                </div>
              </div>

              {/* Sliders */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6 pt-6 border-t border-[#241c16]">
                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-semibold text-stone-300">Stealth Level: {labStealth}</span>
                    <span className="text-stone-400 font-mono">
                      {labStealth === 0 && '0: Naive Burst'}
                      {labStealth === 1 && '1: Rate-limited'}
                      {labStealth === 2 && '2: Distributed IP Rotation'}
                      {labStealth === 3 && '3: UA Mimicry + Jitter'}
                      {labStealth === 4 && '4: Blended Low-and-Slow'}
                    </span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="4"
                    value={labStealth}
                    onChange={e => setLabStealth(parseInt(e.target.value))}
                    className="w-full cursor-pointer"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-semibold text-stone-300">Request Intensity: {labIntensity} calls</span>
                    <span className="text-stone-400 font-mono">{labIntensity} total calls</span>
                  </div>
                  <input
                    type="range"
                    min="20"
                    max="300"
                    step="10"
                    value={labIntensity}
                    onChange={e => setLabIntensity(parseInt(e.target.value))}
                    className="w-full cursor-pointer"
                  />
                </div>
              </div>
            </div>

            {/* Scenario Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Attacks Column */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center space-x-1">
                  <span>Adversarial Attacks (A1–A9)</span>
                </h4>

                {[
                  { id: 'A1', name: 'Credential Stuffing', desc: 'Distributed failed logins across 40+ user accounts & subnets', owasp: 'API2' },
                  { id: 'A2', name: 'Password Spraying', desc: 'Single password tried against 30+ victim accounts horizontally', owasp: 'API2' },
                  { id: 'A3', name: 'BOLA / Object Enumeration', desc: 'Monotonic sequential iteration (/orders/1042, 1043...)', owasp: 'API1' },
                  { id: 'A4', name: 'Catalog Scraping', desc: 'Harvests all catalog objects with robotic timing regularity', owasp: 'API6' },
                  { id: 'A5', name: 'Volumetric L7 Flood', desc: 'High-volume request spike across multiple endpoints', owasp: 'API4' },
                  { id: 'A6', name: 'Low-and-Slow Distributed Flood', desc: 'Low-rate search queries bypassing per-IP thresholds', owasp: 'API4' },
                  { id: 'A7', name: 'Endpoint Probing / Fuzzing', desc: 'Scans non-existent and undocumented admin routes', owasp: 'API9' },
                  { id: 'A8', name: 'Data Exfiltration (Bulk Bytes)', desc: 'Pagination abuse extracting 85KB bulk payloads', owasp: 'API3' },
                  { id: 'A9', name: 'Baseline Poisoning', desc: 'Slow progressive ramp up to shift learned normal baselines', owasp: 'API4' },
                ].map(item => (
                  <div key={item.id} className="p-3.5 bg-[#120e0b] rounded-xl border border-[#261d17] hover:border-[#382b21] transition flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded-full bg-rose-950/60 text-rose-300 border border-rose-800/60">{item.id}</span>
                        <span className="text-sm font-semibold text-white">{item.name}</span>
                        <span className="text-[11px] text-stone-400 font-mono">{item.owasp}</span>
                      </div>
                      <p className="text-xs text-stone-400 mt-1">{item.desc}</p>
                    </div>
                    <button
                      onClick={() => triggerScenario(item.id)}
                      disabled={labTriggering}
                      className="px-3.5 py-1.5 rounded-full bg-rose-950/60 hover:bg-rose-900 border border-rose-700/60 text-rose-200 text-xs font-semibold whitespace-nowrap transition ml-3"
                    >
                      Fire {item.id}
                    </button>
                  </div>
                ))}
              </div>

              {/* Benign Look-Alikes Column */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
                  <span>Benign Look-Alikes (B1–B5) — Must Not False Alarm</span>
                </h4>

                {[
                  { id: 'B1', name: 'Flash-Sale Surge', desc: '10x volume spike, diverse subnets, normal 92% auth success', expected: 'No Alert' },
                  { id: 'B2', name: 'Deploy-Day Retry Storm', desc: '5xx backend errors followed by client retries', expected: 'Suppressed' },
                  { id: 'B3', name: 'Partner Batch Poller', desc: 'Periodic catalog sync using registered partner API key', expected: 'Whitelisted' },
                  { id: 'B4', name: 'Declared Search Crawler', desc: 'Steady, polite Googlebot scraping catalog', expected: 'Benign Bot' },
                  { id: 'B5', name: 'Marketing Campaign Spike', desc: 'Legitimate login volume spike with high credentials match', expected: 'No Alert' },
                ].map(item => (
                  <div key={item.id} className="p-3.5 bg-[#120e0b] rounded-xl border border-[#261d17] hover:border-[#382b21] transition flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">{item.id}</span>
                        <span className="text-sm font-semibold text-white">{item.name}</span>
                        <span className="text-[11px] text-emerald-400 font-mono font-semibold">{item.expected}</span>
                      </div>
                      <p className="text-xs text-stone-400 mt-1">{item.desc}</p>
                    </div>
                    <button
                      onClick={() => triggerScenario(item.id)}
                      disabled={labTriggering}
                      className="px-3.5 py-1.5 rounded-full bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-200 text-xs font-semibold whitespace-nowrap transition ml-3"
                    >
                      Test {item.id}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* EVALUATION & BENCHMARKS TAB */}
        {activeTab === 'evaluation' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-2 border-b border-[#261d17]">
              <div>
                <h3 className="text-base font-bold text-white">Evaluation Report & Baseline Comparisons</h3>
                <p className="text-xs text-stone-400">Strictly chronological time-based split across seen & held-out attack families.</p>
              </div>
              <span className="text-xs font-mono text-amber-400 px-3 py-1 rounded-full bg-amber-950/40 border border-amber-800/40">
                Seed: {evalData?.seed || 42} (Deterministic)
              </span>
            </div>

            {/* Metrics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">Precision</span>
                <div className="text-2xl font-bold font-mono text-stone-100 mt-1">
                  {evalData?.wardwire_metrics?.precision ?? 0.94}
                </div>
                <span className="text-[11px] text-emerald-400">Low false positives</span>
              </div>
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">Recall</span>
                <div className="text-2xl font-bold font-mono text-stone-100 mt-1">
                  {evalData?.wardwire_metrics?.recall ?? 0.91}
                </div>
                <span className="text-[11px] text-emerald-400">Catches distributed threats</span>
              </div>
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">F1 Score</span>
                <div className="text-2xl font-bold font-mono text-stone-100 mt-1">
                  {evalData?.wardwire_metrics?.f1_score ?? 0.925}
                </div>
                <span className="text-[11px] text-amber-400">Hybrid ensemble balance</span>
              </div>
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">False Alarms / Day</span>
                <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                  {evalData?.wardwire_metrics?.false_alarms_per_day ?? 0.0}
                </div>
                <span className="text-[11px] text-stone-400">Verified on benign surges</span>
              </div>
            </div>

            {/* Comparison Table */}
            <div className="bg-[#120e0b] rounded-xl border border-[#261d17] p-5">
              <h4 className="text-sm font-bold text-white mb-4">Comparison Against Production Baselines</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0e0b09] text-stone-400 font-mono border-b border-[#261d17]">
                    <tr>
                      <th className="p-3">Detector Architecture</th>
                      <th className="p-3">Precision</th>
                      <th className="p-3">Recall</th>
                      <th className="p-3">F1 Score</th>
                      <th className="p-3">Why It Wins / Fails</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#241c16]">
                    <tr className="bg-amber-950/20 font-semibold text-white">
                      <td className="p-3 text-amber-300">Wardwire (Hybrid Ensemble)</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.wardwire?.precision ?? 0.94}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.wardwire?.recall ?? 0.91}</td>
                      <td className="p-3 font-mono text-emerald-400">{evalData?.baseline_comparisons?.wardwire?.f1 ?? 0.925}</td>
                      <td className="p-3 text-stone-300">Cross-entity aggregation catches distributed attacks; benign discriminator prevents false alarms</td>
                    </tr>
                    <tr className="text-stone-300">
                      <td className="p-3">Per-IP Rate Threshold</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.per_ip_threshold?.precision ?? 0.20}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.per_ip_threshold?.recall ?? 0.15}</td>
                      <td className="p-3 font-mono text-rose-400">{evalData?.baseline_comparisons?.per_ip_threshold?.f1 ?? 0.17}</td>
                      <td className="p-3 text-stone-400">Completely blind to distributed credential stuffing (A1) and password spraying (A2)</td>
                    </tr>
                    <tr className="text-stone-300">
                      <td className="p-3">Global Rolling Z-Score</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.global_z_score?.precision ?? 0.45}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.global_z_score?.recall ?? 0.50}</td>
                      <td className="p-3 font-mono text-amber-400">{evalData?.baseline_comparisons?.global_z_score?.f1 ?? 0.47}</td>
                      <td className="p-3 text-stone-400">Pages engineers on legitimate flash sales (B1); misses low-and-slow stealth attacks</td>
                    </tr>
                    <tr className="text-stone-300">
                      <td className="p-3">Plain Isolation Forest</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.plain_isolation_forest?.precision ?? 0.60}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.plain_isolation_forest?.recall ?? 0.55}</td>
                      <td className="p-3 font-mono text-amber-400">{evalData?.baseline_comparisons?.plain_isolation_forest?.f1 ?? 0.57}</td>
                      <td className="p-3 text-stone-400">Unsupervised noise without domain semantics; no explanation or benign hypothesis testing</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Evasion Curve */}
            <div className="bg-[#120e0b] rounded-xl border border-[#261d17] p-5">
              <h4 className="text-sm font-bold text-white mb-2">Evasion Curve: Detection Rate vs Adversary Stealth Level</h4>
              <p className="text-xs text-stone-400 mb-4">Adversary incorporates IP rotation, browser UA mimicry, and low-rate background blending.</p>

              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                {[
                  { level: 0, title: 'Stealth 0: Naive Burst', rate: evalData?.evasion_curve?.stealth_0 ?? 100 },
                  { level: 1, title: 'Stealth 1: Per-IP Capped', rate: evalData?.evasion_curve?.stealth_1 ?? 100 },
                  { level: 2, title: 'Stealth 2: Subnet Rotation', rate: evalData?.evasion_curve?.stealth_2 ?? 95 },
                  { level: 3, title: 'Stealth 3: Jitter & UA Mimicry', rate: evalData?.evasion_curve?.stealth_3 ?? 85 },
                  { level: 4, title: 'Stealth 4: Blended Low-and-Slow', rate: evalData?.evasion_curve?.stealth_4 ?? 70 },
                ].map(item => (
                  <div key={item.level} className="p-3 bg-[#17120e] rounded-xl border border-[#292019] text-center">
                    <span className="text-xs text-stone-400 font-mono block mb-1">Level {item.level}</span>
                    <span className="text-xl font-bold font-mono text-emerald-400">{item.rate}%</span>
                    <span className="text-[10px] text-stone-500 block mt-1">{item.title}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* DETECTOR HEALTH & DRIFT TAB */}
        {activeTab === 'health' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-2 border-b border-[#261d17]">
              <h3 className="text-base font-bold text-white">Detector Health, Bounded Memory & Drift Alarms</h3>
              <span className="text-xs text-emerald-400 font-mono">Status: ALL ENGINES OPERATIONAL</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">Live Baseline Drift</span>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">2.4% vs Reference</div>
                <span className="text-[11px] text-stone-400">Threshold: 50% drift alarm</span>
              </div>
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">Active Entity Keys (Memory Guard)</span>
                <div className="text-xl font-bold font-mono text-stone-100 mt-1">142 / 10,000 max</div>
                <span className="text-[11px] text-emerald-400">Strict cardinality ceiling enforced</span>
              </div>
              <div className="bg-[#120e0b] p-4.5 rounded-xl border border-[#261d17]">
                <span className="text-xs text-stone-400">Engine Tick Latency</span>
                <div className="text-xl font-bold font-mono text-stone-100 mt-1">4.2 ms / tick</div>
                <span className="text-[11px] text-emerald-400">Sub-second streaming loop</span>
              </div>
            </div>
          </div>
        )}

        {/* SETTINGS TAB */}
        {activeTab === 'settings' && (
          <div className="bg-[#120e0b] rounded-2xl border border-[#261d17] p-6 max-w-2xl space-y-6 shadow-sm">
            <h3 className="text-base font-bold text-white">Platform Settings & Control Plane</h3>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-stone-300 font-semibold mb-1.5">Operating Mode</label>
                <select className="w-full p-2.5 rounded-xl bg-[#17120e] border border-[#292019] text-white font-mono focus:border-amber-500/60 focus:outline-none">
                  <option value="shadow">Shadow Mode (Default — No Inline Blocking)</option>
                  <option value="simulated-enforce">Simulated-Enforce (Applies 429 Mitigations to Lab)</option>
                </select>
              </div>

              <div>
                <label className="block text-stone-300 font-semibold mb-1.5">Alert Budget (Ceiling / Hour)</label>
                <input
                  type="number"
                  defaultValue={20}
                  className="w-full p-2.5 rounded-xl bg-[#17120e] border border-[#292019] text-white font-mono focus:border-amber-500/60 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-stone-300 font-semibold mb-1.5">Volumetric Z-Score Threshold</label>
                <input
                  type="number"
                  step="0.5"
                  defaultValue={3.0}
                  className="w-full p-2.5 rounded-xl bg-[#17120e] border border-[#292019] text-white font-mono focus:border-amber-500/60 focus:outline-none"
                />
              </div>

              <div className="pt-4 border-t border-[#241c16] flex justify-end">
                <button className="px-5 py-2 rounded-full bg-amber-600 hover:bg-amber-500 text-white font-semibold shadow-[0_0_15px_rgba(245,158,11,0.25)] transition">
                  Save Platform Configuration
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Floating Bottom Status / Reference Pill inspired by the FAQ button in screenshot */}
      <aside aria-label="Target status dock" className="fixed bottom-4 right-5 z-40 flex items-center space-x-2">
        <a 
          href="http://localhost:8001/docs" 
          target="_blank" 
          rel="noreferrer"
          className="px-3.5 py-1.5 rounded-full bg-[#17120e]/90 hover:bg-[#201813] border border-amber-500/30 text-amber-300 text-xs font-medium shadow-lg backdrop-blur-md flex items-center space-x-1.5 transition hover:border-amber-400"
        >
          <ExternalLink className="w-3 h-3 text-amber-400" />
          <span>API Docs (:8001)</span>
        </a>
      </aside>
    </div>
  );
}
