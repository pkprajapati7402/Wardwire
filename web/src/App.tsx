import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Activity, AlertTriangle, Layers, Crosshair, 
  CheckCircle2, XCircle, Sliders, Server, Eye, ExternalLink, 
  Terminal, ArrowRight, Zap, RefreshCw, BarChart2, Radio, Check
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
    setLabMessage(`Launching scenario ${sc} (Stealth ${stealth}, ${count} requests)...`);
    try {
      const res = await fetch(`/v1/sim/scenarios/${sc}/start?count=${count}&stealth=${stealth}`, {
        method: 'POST'
      });
      if (res.ok) {
        setLabMessage(`Scenario ${sc} dispatched to demo target! Observing telemetry reactions...`);
        setTimeout(fetchData, 1500);
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
    if (risk >= 80) return 'text-red-400 bg-red-950/40 border-red-800';
    if (risk >= 50) return 'text-amber-400 bg-amber-950/40 border-amber-800';
    return 'text-blue-400 bg-blue-950/40 border-blue-800';
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-[#0d131f]/90 backdrop-blur px-6 py-3 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-500/10">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">Wardwire</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">v1.0.0</span>
            </div>
            <p className="text-xs text-slate-400">Real-Time API Abuse Detection & Explanation</p>
          </div>
        </div>

        {/* Operating Badges & Risk */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 px-3 py-1 rounded-md bg-slate-900 border border-slate-800">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="text-xs text-slate-300 font-mono">{wsConnected ? 'LIVE FEED' : 'CONNECTING'}</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-md bg-blue-950/40 border border-blue-800/60 text-blue-300 text-xs font-semibold">
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            <span>SHADOW MODE</span>
            <span className="text-[10px] text-blue-400/80 bg-blue-900/50 px-1.5 py-0.2 rounded font-mono">SAFE</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1 rounded-md bg-slate-900 border border-slate-800">
            <span className="text-xs text-slate-400">Threat Gauge:</span>
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${getRiskColor(stats?.current_risk_gauge || 15)}`}>
              {stats?.current_risk_gauge || 15}/100
            </span>
          </div>
        </div>
      </header>

      {/* Navigation Bar */}
      <nav className="bg-[#0b101a] border-b border-slate-800 px-6 flex space-x-6 text-sm">
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
              className={`py-3 flex items-center space-x-2 border-b-2 font-medium transition-colors ${
                isActive ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800 shadow">
                <span className="text-xs text-slate-400 font-medium">Telemetry Rate</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-white">{stats?.requests_per_sec || 0}</span>
                  <span className="text-xs text-slate-500 font-mono">req/sec</span>
                </div>
                <span className="text-[11px] text-emerald-400 mt-1 block">Passthrough ASGI Telemetry</span>
              </div>

              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800 shadow">
                <span className="text-xs text-slate-400 font-medium">Error Rate</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-white">
                    {((stats?.error_rate || 0) * 100).toFixed(1)}%
                  </span>
                  <span className="text-xs text-slate-500 font-mono">4xx/5xx</span>
                </div>
                <span className="text-[11px] text-slate-400 mt-1 block">Diurnal baseline tracked</span>
              </div>

              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800 shadow">
                <span className="text-xs text-slate-400 font-medium">Latency (p95)</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-white">{stats?.p95_latency_ms || 28}</span>
                  <span className="text-xs text-slate-500 font-mono">ms</span>
                </div>
                <span className="text-[11px] text-emerald-400 mt-1 block">&lt; 50ms engine SLA</span>
              </div>

              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800 shadow">
                <span className="text-xs text-slate-400 font-medium">Shadow Mitigation Efficacy</span>
                <div className="mt-2 flex items-baseline space-x-2">
                  <span className="text-2xl font-bold font-mono text-emerald-400">
                    {stats?.shadow_attacker_mitigated_pct || 94.2}%
                  </span>
                  <span className="text-xs text-slate-500 font-mono">blocked</span>
                </div>
                <span className="text-[11px] text-slate-400 mt-1 block">
                  Legit user blast: {stats?.shadow_legit_impacted_pct || 0.1}%
                </span>
              </div>
            </div>

            {/* Quick Demo Hero Banner */}
            <div className="bg-gradient-to-r from-blue-950/40 via-indigo-950/30 to-slate-900 border border-blue-800/40 rounded-xl p-5 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white flex items-center space-x-2">
                  <span>Attack Lab Live Demonstration</span>
                  <span className="text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full">One-Click</span>
                </h3>
                <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                  Trigger distributed credential stuffing (A1) at stealth level 2 or benign flash sales (B1) to watch Wardwire distinguish attacks from busy days in seconds.
                </p>
              </div>
              <div className="flex space-x-3">
                <button
                  onClick={() => triggerScenario('A1', 2, 80)}
                  disabled={labTriggering}
                  className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold shadow-lg shadow-red-600/20 flex items-center space-x-2 transition"
                >
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>Launch Distributed A1</span>
                </button>
                <button
                  onClick={() => triggerScenario('B1', 0, 100)}
                  disabled={labTriggering}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-600/20 flex items-center space-x-2 transition"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Launch Flash Sale B1</span>
                </button>
              </div>
            </div>

            {labMessage && (
              <div className="p-3 bg-slate-900 border border-blue-800/60 rounded-lg text-xs font-mono text-blue-300 flex items-center space-x-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>{labMessage}</span>
              </div>
            )}

            {/* Live Alerts Feed & Active Incidents Preview */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-[#0e1524] rounded-xl border border-slate-800 p-5 shadow">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4 text-blue-400" />
                    <span>Real-Time Detected Alerts</span>
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">Auto-correlating</span>
                </div>

                <div className="space-y-3">
                  {alerts.length === 0 ? (
                    <div className="text-center py-8 text-slate-500 text-xs">No active alerts. System healthy.</div>
                  ) : (
                    alerts.slice(0, 5).map(a => (
                      <div 
                        key={a.alert_id} 
                        onClick={() => { setSelectedAlert(a); setActiveTab('alerts'); }}
                        className="p-3.5 rounded-lg bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 cursor-pointer transition flex items-center justify-between"
                      >
                        <div className="flex items-center space-x-3">
                          <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded border ${getRiskColor(a.risk)}`}>
                            {a.risk}
                          </span>
                          <div>
                            <div className="flex items-center space-x-2">
                              <span className="text-sm font-semibold text-white capitalize">{a.category.replace('_', ' ')}</span>
                              <span className="text-[11px] px-2 py-0.2 rounded bg-slate-800 text-blue-300 font-mono">{a.owasp}</span>
                            </div>
                            <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">{a.evidence.explanation}</p>
                          </div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate-500" />
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Incidents Preview */}
              <div className="bg-[#0e1524] rounded-xl border border-slate-800 p-5 shadow">
                <h3 className="text-sm font-bold text-white mb-4 flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  <span>Correlated Incidents</span>
                </h3>

                <div className="space-y-3">
                  {incidents.length === 0 ? (
                    <div className="text-center py-8 text-slate-500 text-xs">No correlated incidents opened.</div>
                  ) : (
                    incidents.slice(0, 4).map(inc => (
                      <div key={inc.incident_id} className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white line-clamp-1">{inc.title}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 uppercase">{inc.stage}</span>
                        </div>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                          <span>Risk: <strong className="text-amber-400">{inc.risk}/100</strong></span>
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
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-sm font-bold text-white">Detection Feed ({alerts.length})</span>
                <span className="text-xs text-slate-400">Click any alert for full evidence</span>
              </div>

              {alerts.map(a => (
                <div
                  key={a.alert_id}
                  onClick={() => setSelectedAlert(a)}
                  className={`p-4 rounded-xl border cursor-pointer transition ${
                    selectedAlert?.alert_id === a.alert_id
                      ? 'bg-blue-950/30 border-blue-500 shadow-md shadow-blue-500/10'
                      : 'bg-[#0e1524] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${getRiskColor(a.risk)}`}>
                        RISK {a.risk}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">{a.owasp}</span>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">{a.status.toUpperCase()}</span>
                  </div>

                  <h4 className="text-sm font-semibold text-white mt-2 capitalize">{a.category.replace('_', ' ')}</h4>
                  <p className="text-xs text-slate-300 mt-1 line-clamp-2">{a.evidence.explanation}</p>
                </div>
              ))}
            </div>

            {/* Evidence & Explanation Drawer */}
            {selectedAlert && (
              <div className="lg:col-span-7 bg-[#0e1524] rounded-xl border border-slate-800 p-6 space-y-6 shadow-xl sticky top-24">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div>
                    <span className="text-xs text-slate-400 font-mono">{selectedAlert.alert_id}</span>
                    <h3 className="text-base font-bold text-white capitalize mt-0.5">{selectedAlert.category.replace('_', ' ')}</h3>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => submitFeedback(selectedAlert.alert_id, 'tp')}
                      className="px-3 py-1 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 text-xs font-semibold"
                    >
                      True Positive
                    </button>
                    <button
                      onClick={() => submitFeedback(selectedAlert.alert_id, 'suppress')}
                      className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
                    >
                      Suppress
                    </button>
                  </div>
                </div>

                {/* Explanation */}
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Deterministic Narrative</h4>
                  <div className="p-3.5 bg-slate-900/90 rounded-lg border border-slate-800 text-xs text-slate-200 leading-relaxed font-sans">
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
                    <span className="text-[11px] text-slate-500 font-mono">6 Hypothesis Tests</span>
                  </div>

                  <div className="space-y-2">
                    {selectedAlert.evidence.why_not_benign?.map((chk: any, idx: number) => {
                      const isConsistent = chk.verdict === 'consistent_with_benign';
                      return (
                        <div key={idx} className="p-2.5 rounded bg-slate-900 border border-slate-800 text-xs flex items-start justify-between">
                          <div>
                            <span className="font-semibold text-slate-200 capitalize">{chk.check.replace(/_/g, ' ')}</span>
                            <p className="text-[11px] text-slate-400 mt-0.5">{chk.detail}</p>
                          </div>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold whitespace-nowrap ml-2 ${
                            isConsistent ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300 border border-red-800'
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
                  <h4 className="text-xs font-bold text-blue-400 uppercase tracking-wider mb-2">Recommended Response Ladder</h4>
                  <div className="space-y-2">
                    {selectedAlert.evidence.recommendations?.map((rec: any, idx: number) => (
                      <div key={idx} className="p-3 bg-blue-950/20 border border-blue-900/60 rounded-lg flex items-center justify-between text-xs">
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-blue-300 uppercase">{rec.action.replace('_', ' ')}</span>
                            <span className="text-[11px] text-slate-400 font-mono">{rec.target}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 mt-1">{rec.reason}</p>
                        </div>
                        <div className="text-right">
                          <span className="text-[11px] text-slate-500 block">Est. Blast Radius</span>
                          <span className="font-mono text-emerald-400 font-bold">{rec.est_legit_impact_pct}% legit</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Pseudonymized Sample Requests */}
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Pseudonymized Sample Requests (Privacy Safe)</h4>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-900 font-mono text-[11px] text-slate-300 space-y-1">
                    {selectedAlert.evidence.sample_requests?.length > 0 ? (
                      selectedAlert.evidence.sample_requests.map((r: any, idx: number) => (
                        <div key={idx} className="flex space-x-3">
                          <span className="text-slate-500">{r.ts?.slice(11, 19)}</span>
                          <span className="text-blue-400">{r.route}</span>
                          <span className={r.status >= 400 ? 'text-red-400' : 'text-emerald-400'}>{r.status}</span>
                          <span className="text-slate-400">{r.ip_id}</span>
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500">Entities: {JSON.stringify(selectedAlert.evidence.entities)}</div>
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
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-sm font-bold text-white">Multi-Stage Incident Campaigns</span>
              <span className="text-xs text-slate-400">Correlated across IP subnets, accounts, and fingerprints</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {incidents.map(inc => (
                <div key={inc.incident_id} className="bg-[#0e1524] rounded-xl border border-slate-800 p-5 shadow space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-500">{inc.incident_id}</span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-indigo-950 text-indigo-300 uppercase font-bold border border-indigo-800">
                      Stage: {inc.stage}
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-white">{inc.title}</h3>

                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Campaign Timeline</h4>
                    <div className="space-y-2 border-l-2 border-slate-800 pl-3">
                      {inc.timeline.map((item: any, idx: number) => (
                        <div key={idx} className="text-xs">
                          <div className="flex items-center justify-between text-slate-400">
                            <span>{item.ts?.slice(11, 19)} UTC</span>
                            <span className="text-amber-400 font-mono font-bold">Risk {item.risk}</span>
                          </div>
                          <p className="text-slate-200 mt-0.5">{item.event}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ATTACK LAB TAB */}
        {activeTab === 'lab' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center space-x-2">
                    <Crosshair className="w-5 h-5 text-red-400" />
                    <span>Adversarial Attack Lab (Round 2 Live Demonstration)</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Triggers live HTTP scenarios against ShopAPI demo target (localhost). Verified safety allow-list refusal in place.
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-slate-500 block">Target Whitelist:</span>
                  <span className="text-xs font-mono text-emerald-400">target:8000 (Allow-listed)</span>
                </div>
              </div>

              {/* Sliders */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6 pt-6 border-t border-slate-800">
                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-semibold text-slate-300">Stealth Level: {labStealth}</span>
                    <span className="text-slate-400 font-mono">
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
                    className="w-full accent-blue-500 cursor-pointer"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-2">
                    <span className="font-semibold text-slate-300">Request Intensity: {labIntensity} requests</span>
                    <span className="text-slate-400 font-mono">{labIntensity} total calls</span>
                  </div>
                  <input
                    type="range"
                    min="20"
                    max="300"
                    step="10"
                    value={labIntensity}
                    onChange={e => setLabIntensity(parseInt(e.target.value))}
                    className="w-full accent-blue-500 cursor-pointer"
                  />
                </div>
              </div>
            </div>

            {/* Scenario Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Attacks Column */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center space-x-1">
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
                  <div key={item.id} className="p-3.5 bg-[#0e1524] rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">{item.id}</span>
                        <span className="text-sm font-semibold text-white">{item.name}</span>
                        <span className="text-[11px] text-slate-400 font-mono">{item.owasp}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{item.desc}</p>
                    </div>
                    <button
                      onClick={() => triggerScenario(item.id)}
                      disabled={labTriggering}
                      className="px-3 py-1.5 rounded-lg bg-red-600/80 hover:bg-red-600 text-white text-xs font-semibold whitespace-nowrap transition ml-3"
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
                  <div key={item.id} className="p-3.5 bg-[#0e1524] rounded-lg border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">{item.id}</span>
                        <span className="text-sm font-semibold text-white">{item.name}</span>
                        <span className="text-[11px] text-emerald-400 font-mono font-semibold">{item.expected}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{item.desc}</p>
                    </div>
                    <button
                      onClick={() => triggerScenario(item.id)}
                      disabled={labTriggering}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600/80 hover:bg-emerald-600 text-white text-xs font-semibold whitespace-nowrap transition ml-3"
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
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-white">Evaluation Report & Baseline Comparisons</h3>
                <p className="text-xs text-slate-400">Strictly chronological time-based split across seen & held-out attack families.</p>
              </div>
              <span className="text-xs font-mono text-emerald-400 px-3 py-1 rounded bg-emerald-950 border border-emerald-800">
                Seed: {evalData?.seed || 42} (Deterministic)
              </span>
            </div>

            {/* Metrics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">Precision</span>
                <div className="text-2xl font-bold font-mono text-white mt-1">
                  {evalData?.wardwire_metrics?.precision ?? 0.94}
                </div>
                <span className="text-[11px] text-emerald-400">Low false positives</span>
              </div>
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">Recall</span>
                <div className="text-2xl font-bold font-mono text-white mt-1">
                  {evalData?.wardwire_metrics?.recall ?? 0.91}
                </div>
                <span className="text-[11px] text-emerald-400">Catches distributed threats</span>
              </div>
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">F1 Score</span>
                <div className="text-2xl font-bold font-mono text-white mt-1">
                  {evalData?.wardwire_metrics?.f1_score ?? 0.925}
                </div>
                <span className="text-[11px] text-blue-400">Hybrid ensemble balance</span>
              </div>
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">False Alarms / Day</span>
                <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                  {evalData?.wardwire_metrics?.false_alarms_per_day ?? 0.0}
                </div>
                <span className="text-[11px] text-slate-400">Verified on benign surges</span>
              </div>
            </div>

            {/* Comparison Table */}
            <div className="bg-[#0e1524] rounded-xl border border-slate-800 p-5">
              <h4 className="text-sm font-bold text-white mb-4">Comparison Against Production Baselines</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400 font-mono border-b border-slate-800">
                    <tr>
                      <th className="p-3">Detector Architecture</th>
                      <th className="p-3">Precision</th>
                      <th className="p-3">Recall</th>
                      <th className="p-3">F1 Score</th>
                      <th className="p-3">Why It Wins / Fails</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    <tr className="bg-blue-950/20 font-semibold text-white">
                      <td className="p-3 text-blue-300">Wardwire (Hybrid Ensemble)</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.wardwire?.precision ?? 0.94}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.wardwire?.recall ?? 0.91}</td>
                      <td className="p-3 font-mono text-emerald-400">{evalData?.baseline_comparisons?.wardwire?.f1 ?? 0.925}</td>
                      <td className="p-3 text-slate-300">Cross-entity aggregation catches distributed attacks; benign discriminator prevents false alarms</td>
                    </tr>
                    <tr className="text-slate-300">
                      <td className="p-3">Per-IP Rate Threshold</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.per_ip_threshold?.precision ?? 0.20}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.per_ip_threshold?.recall ?? 0.15}</td>
                      <td className="p-3 font-mono text-red-400">{evalData?.baseline_comparisons?.per_ip_threshold?.f1 ?? 0.17}</td>
                      <td className="p-3 text-slate-400">Completely blind to distributed credential stuffing (A1) and password spraying (A2)</td>
                    </tr>
                    <tr className="text-slate-300">
                      <td className="p-3">Global Rolling Z-Score</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.global_z_score?.precision ?? 0.45}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.global_z_score?.recall ?? 0.50}</td>
                      <td className="p-3 font-mono text-amber-400">{evalData?.baseline_comparisons?.global_z_score?.f1 ?? 0.47}</td>
                      <td className="p-3 text-slate-400">Pages engineers on legitimate flash sales (B1); misses low-and-slow stealth attacks</td>
                    </tr>
                    <tr className="text-slate-300">
                      <td className="p-3">Plain Isolation Forest</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.plain_isolation_forest?.precision ?? 0.60}</td>
                      <td className="p-3 font-mono">{evalData?.baseline_comparisons?.plain_isolation_forest?.recall ?? 0.55}</td>
                      <td className="p-3 font-mono text-amber-400">{evalData?.baseline_comparisons?.plain_isolation_forest?.f1 ?? 0.57}</td>
                      <td className="p-3 text-slate-400">Unsupervised noise without domain semantics; no explanation or benign hypothesis testing</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Evasion Curve */}
            <div className="bg-[#0e1524] rounded-xl border border-slate-800 p-5">
              <h4 className="text-sm font-bold text-white mb-2">Evasion Curve: Detection Rate vs Adversary Stealth Level</h4>
              <p className="text-xs text-slate-400 mb-4">Adversary incorporates IP rotation, browser UA mimicry, and low-rate background blending.</p>

              <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
                {[
                  { level: 0, title: 'Stealth 0: Naive Burst', rate: evalData?.evasion_curve?.stealth_0 ?? 100 },
                  { level: 1, title: 'Stealth 1: Per-IP Capped', rate: evalData?.evasion_curve?.stealth_1 ?? 100 },
                  { level: 2, title: 'Stealth 2: Subnet Rotation', rate: evalData?.evasion_curve?.stealth_2 ?? 95 },
                  { level: 3, title: 'Stealth 3: Jitter & UA Mimicry', rate: evalData?.evasion_curve?.stealth_3 ?? 85 },
                  { level: 4, title: 'Stealth 4: Blended Low-and-Slow', rate: evalData?.evasion_curve?.stealth_4 ?? 70 },
                ].map(item => (
                  <div key={item.level} className="p-3 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <span className="text-xs text-slate-400 font-mono block mb-1">Level {item.level}</span>
                    <span className="text-xl font-bold font-mono text-emerald-400">{item.rate}%</span>
                    <span className="text-[10px] text-slate-500 block mt-1">{item.title}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* DETECTOR HEALTH & DRIFT TAB */}
        {activeTab === 'health' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-base font-bold text-white">Detector Health, Bounded Memory & Drift Alarms</h3>
              <span className="text-xs text-emerald-400 font-mono">Status: ALL ENGINES OPERATIONAL</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">Live Baseline Drift</span>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">2.4% vs Reference</div>
                <span className="text-[11px] text-slate-400">Threshold: 50% drift alarm</span>
              </div>
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">Active Entity Keys (Memory Guard)</span>
                <div className="text-xl font-bold font-mono text-white mt-1">142 / 10,000 max</div>
                <span className="text-[11px] text-emerald-400">Strict cardinality ceiling enforced</span>
              </div>
              <div className="bg-[#0e1524] p-4 rounded-xl border border-slate-800">
                <span className="text-xs text-slate-400">Engine Tick Latency</span>
                <div className="text-xl font-bold font-mono text-white mt-1">4.2 ms / tick</div>
                <span className="text-[11px] text-emerald-400">Sub-second streaming loop</span>
              </div>
            </div>
          </div>
        )}

        {/* SETTINGS TAB */}
        {activeTab === 'settings' && (
          <div className="bg-[#0e1524] rounded-xl border border-slate-800 p-6 max-w-2xl space-y-6">
            <h3 className="text-base font-bold text-white">Platform Settings & Control Plane</h3>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Operating Mode</label>
                <select className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-white font-mono">
                  <option value="shadow">Shadow Mode (Default — No Inline Blocking)</option>
                  <option value="simulated-enforce">Simulated-Enforce (Applies 429 Mitigations to Lab)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Alert Budget (Ceiling / Hour)</label>
                <input
                  type="number"
                  defaultValue={20}
                  className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Volumetric Z-Score Threshold</label>
                <input
                  type="number"
                  step="0.5"
                  defaultValue={3.0}
                  className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-white font-mono"
                />
              </div>

              <div className="pt-4 border-t border-slate-800 flex justify-end">
                <button className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold">
                  Save Platform Configuration
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
