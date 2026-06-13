import { useState, useEffect, useMemo, useRef } from 'react';
import {
  Shield, Activity, AlertTriangle, CheckCircle, RefreshCw,
  TrendingUp, Search, Database, BarChart3, Clock, Globe,
  LogOut, Settings, Cpu, ChevronRight, Zap, Eye, Lock,
  X, FileText
} from 'lucide-react';
import './App.css';
import { httpJson } from './utils/http.js';

/* ─────────────────────────────────────────────
   Animated counter hook – counts up from 0 to value
───────────────────────────────────────────── */
function useCountUp(target, duration = 1200) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (!target) return;
    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) { setCount(target); clearInterval(timer); }
      else setCount(Math.floor(start));
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return count;
}

/* ─────────────────────────────────────────────
   Scanning line animation component
───────────────────────────────────────────── */
function ScanLine() {
  return <div className="scan-line" />;
}

/* ─────────────────────────────────────────────
   Main App Component
───────────────────────────────────────────── */
function App() {
  const [scans, setScans]                   = useState([]);
  const [loading, setLoading]               = useState(true);
  const [error, setError]                   = useState(null);
  const [lastUpdate, setLastUpdate]         = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [activeTab, setActiveTab]           = useState('dashboard');
  const [searchTerm, setSearchTerm]         = useState('');

  /* URL Scanner state */
  const [scanUrl, setScanUrl]       = useState('');
  const [scanning, setScanning]     = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const isBlacklistHit = (r) =>
    !!r && (r.blacklist_hit === true || /blacklisted\s*url/i.test(r.reason || ''));

  const getUrlMeta = (raw) => {
    try {
      const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
      const host = u.hostname || '';
      const path = (u.pathname || '/') + (u.search || '');
      return {
        host,
        display: host ? `${host}${path === '/' ? '' : path}` : raw,
      };
    } catch {
      return { host: '', display: raw || '' };
    }
  };

  const getEffectiveness = (r) => {
    // "effectiveness" here means how strong the system's decision is (confidence/risk).
    if (!r) return null;
    if (isBlacklistHit(r)) {
      return { label: 'Threat Score', value: 100, tone: 'danger', hint: 'Hard-block (Blacklist)' };
    }
    const mv = r.model_votes;
    if (!mv || !mv.total_votes) {
      // Fallback: show verdict without a numeric score.
      return { label: 'Decision Strength', value: 0, tone: r.result === 'Phishing' ? 'danger' : 'safe', hint: 'No model votes' };
    }
    const pct = Math.round((Math.max(mv.phishing_votes, mv.legitimate_votes) / (mv.total_votes || 1)) * 100);
    const isPhish = r.result === 'Phishing';
    return {
      label: isPhish ? 'Threat Score' : 'Safety Score',
      value: pct,
      tone: isPhish ? 'danger' : 'safe',
      hint: `Votes: ${mv.phishing_votes}/${mv.total_votes} phishing`,
    };
  };

  /* Detail modal state */
  const [selectedScan, setSelectedScan]     = useState(null);
  const [detailLoading, setDetailLoading]   = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);

  /* Live analysis animation refs */
  const [activeLayer, setActiveLayer] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setActiveLayer(l => (l + 1) % 4), 2000);
    return () => clearInterval(t);
  }, []);

  /* ── Fetch detailed scan ── */
  const fetchScanDetails = async (scan) => {
    setDetailLoading(true);
    setSelectedScan(scan);
    setShowDetailModal(true);
    try {
      const fresh = await httpJson(
        `http://127.0.0.1:8000/api/scan/?url=${encodeURIComponent(scan.url)}`,
        { method: 'GET', timeoutMs: 8000 }
      );
      if (fresh) setSelectedScan({ ...scan, ...fresh });
    } catch (e) {
      // Keep modal usable with cached data; surface details in console.
      console.log('Using cached scan data:', e.message);
    } finally {
      setDetailLoading(false);
    }
  };

  /* ── Fetch all scan logs ── */
  const fetchScans = async () => {
    try {
      setLoading(true);
      const data = await httpJson('http://127.0.0.1:8000/api/logs/', { method: 'GET', timeoutMs: 8000 });
      setScans(data.results || data);
      setLastUpdate(new Date());
      setError(null);
      setBackendConnected(true);
    } catch (err) {
      setError(err?.message || 'Cannot connect to backend');
      setBackendConnected(false);
    } finally {
      setLoading(false);
    }
  };

  /* ── Submit URL for scanning ── */
  const handleScanUrl = async () => {
    if (!scanUrl.trim()) return;
    setScanning(true);
    setScanResult(null);
    setError(null);
    try {
      const data = await httpJson('http://127.0.0.1:8000/api/scan/', {
        method: 'POST',
        body: JSON.stringify({ url: scanUrl }),
        timeoutMs: 15000,
      });
      setScanResult(data);
      await fetchScans();
    } catch (err) {
      setError(err?.message ? `Scan failed: ${err.message}` : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  /* ── Auto-refresh every 30s ── */
  useEffect(() => {
    fetchScans();
    const iv = setInterval(() => {
      if (!loading && backendConnected) fetchScans();
    }, 30000);
    return () => clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ── Statistics ── */
  const stats = {
    total:     scans.length,
    phishing:  scans.filter(s => s.result === 'Phishing').length,
    legitimate: scans.filter(s => s.result === 'Legitimate').length,
    get phishingRate()   { return this.total > 0 ? ((this.phishing   / this.total) * 100).toFixed(1) : 0; },
    get legitimateRate() { return this.total > 0 ? ((this.legitimate / this.total) * 100).toFixed(1) : 0; },
  };

  /* ── Weekly chart data ── */
  const getWeeklyStats = () => {
    const weekData = Array.from({ length: 7 }, () => ({ legitimate: 0, phishing: 0 }));
    scans.forEach(scan => {
      if (scan.timestamp) {
        const day = (new Date(scan.timestamp).getDay() + 6) % 7;
        scan.result === 'Phishing' ? weekData[day].phishing++ : weekData[day].legitimate++;
      }
    });
    return weekData;
  };
  const weeklyData = getWeeklyStats();
  const maxCount   = Math.max(...weeklyData.map(d => d.legitimate + d.phishing), 1);

  /* ── Traffic (last 24h) line data for Dashboard chart ── */
  const getTrafficSeries24h = () => {
    // 24 bins: oldest → newest (hourly)
    const bins = Array.from({ length: 24 }, () => ({ legitimate: 0, phishing: 0 }));
    const now = Date.now();
    const from = now - 24 * 60 * 60 * 1000;

    scans.forEach((scan) => {
      if (!scan.timestamp) return;
      const ts = new Date(scan.timestamp).getTime();
      if (!Number.isFinite(ts) || ts < from || ts > now) return;

      const idx = Math.min(
        23,
        Math.max(0, Math.floor((ts - from) / (60 * 60 * 1000)))
      );

      if (scan.result === 'Phishing') bins[idx].phishing += 1;
      else if (scan.result === 'Legitimate') bins[idx].legitimate += 1;
    });

    const maxVal = Math.max(
      1,
      ...bins.map((b) => b.legitimate),
      ...bins.map((b) => b.phishing)
    );

    return { bins, maxVal };
  };

  const buildLinePath = (series, maxVal) => {
    // Matches the existing SVG viewBox: 700x180
    const W = 700;
    const H = 180;
    const PAD_TOP = 18;
    const PAD_BOTTOM = 22;
    const PAD_L = 18;
    const PAD_R = 18;
    const usableH = H - PAD_TOP - PAD_BOTTOM;

    const step = (W - PAD_L - PAD_R) / (series.length - 1 || 1);
    const pts = series.map((v, i) => {
      const y = PAD_TOP + (1 - (v / maxVal)) * usableH;
      const x = PAD_L + i * step;
      return { x, y };
    });

    const line = `M${pts[0].x.toFixed(2)},${pts[0].y.toFixed(2)} ` +
      pts.slice(1).map(p => `L${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(' ');

    const area =
      `${line} L${(W - PAD_R).toFixed(2)},${H.toFixed(2)} L${PAD_L.toFixed(2)},${H.toFixed(2)} Z`;

    return { line, area };
  };

  const traffic = getTrafficSeries24h();
  const legitSeries = traffic.bins.map(b => b.legitimate);
  const phishSeries = traffic.bins.map(b => b.phishing);
  const legitPaths = buildLinePath(legitSeries, traffic.maxVal);
  const phishPaths = buildLinePath(phishSeries, traffic.maxVal);

  const trafficStartMs = useMemo(() => Date.now() - 24 * 60 * 60 * 1000, []);
  const trafficNowMs = Date.now();

  const trafficSvgRef = useRef(null);
  const [trafficHoverIdx, setTrafficHoverIdx] = useState(null);

  const trafficXForIdx = (idx) => {
    const W = 700;
    const PAD_L = 18;
    const PAD_R = 18;
    const step = (W - PAD_L - PAD_R) / (24 - 1);
    return PAD_L + idx * step;
  };

  const trafficTimeForIdx = (idx) => {
    const ms = trafficStartMs + idx * 60 * 60 * 1000;
    return new Date(ms);
  };

  const formatTickTime = (d) =>
    d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const trafficTickLabels = (() => {
    const ticksAgo = [24, 20, 16, 12, 8, 4, 0];
    return ticksAgo.map((h) => {
      const d = new Date(trafficNowMs - h * 60 * 60 * 1000);
      return formatTickTime(d);
    });
  })();

  /* ── Filtered scan list ── */
  const filteredScans = scans.filter(s =>
    s.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.result?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  /* ── CSV export ── */
  const downloadCSV = () => {
    const rows = [
      ['URL', 'Result', 'Reason', 'Date'].join(','),
      ...scans.map(s => {
        const url    = `"${(s.url    || '').replace(/"/g, '""')}"`;
        const reason = `"${(s.reason || '').replace(/"/g, '""')}"`;
        const date   = s.timestamp ? new Date(s.timestamp).toLocaleString() : '';
        return `${url},"${s.result}",${reason},"${date}"`;
      }),
    ].join('\n');
    const blob = new Blob([rows], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href   = URL.createObjectURL(blob);
    link.download = 'phishguard_report.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  /* ── Nav items config ── */
  const navItems = [
    { id: 'dashboard',  icon: BarChart3,  label: 'Dashboard'          },
    { id: 'scanner',    icon: Activity,   label: 'Live Analysis'       },
    { id: 'scans',      icon: Eye,        label: 'Threat Intelligence' },
    { id: 'analytics',  icon: TrendingUp, label: 'Analytics'           },
    { id: 'models',     icon: Cpu,        label: 'Agents Status'       },
  ];

  /* ── Animated stat numbers ── */
  const totalCount    = useCountUp(stats.total);
  const phishCount    = useCountUp(stats.phishing);
  const legitCount    = useCountUp(stats.legitimate);

  /* ════════════════════════════════════════════
     RENDER
  ════════════════════════════════════════════ */
  return (
    <div className="app-shell">

      {/* ── Grid overlay background ── */}
      <div className="grid-bg" />

      {/* ══════════════ SIDEBAR ══════════════ */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>
          <div>
            <div className="brand-name">PHISH<span>GUARD</span></div>
            <div className="brand-sub">SYSTEM SECURE</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <item.icon size={16} />
              <span>{item.label}</span>
              {activeTab === item.id && <ChevronRight size={14} className="nav-arrow" />}
            </button>
          ))}
        </nav>

        {/* System status indicator */}
        <div className="sidebar-status">
          <div className={`status-dot ${backendConnected ? 'online' : 'offline'}`} />
          <span className={backendConnected ? 'text-cyan' : 'text-red'}>
            {backendConnected ? 'System Active' : 'Offline'}
          </span>
        </div>

        <button className="nav-item logout-btn" onClick={() => {}}>
          <LogOut size={16} />
          <span>Logout</span>
        </button>
      </aside>

      {/* ══════════════ MAIN AREA ══════════════ */}
      <main className="main-content">

        {/* ── Top bar ── */}
        <header className="top-bar">
          <div className="location-crumb">
            <span className="crumb-label">LOCATION:</span>
            <span className="crumb-page">
              {activeTab === 'dashboard' && 'DASHBOARD'}
              {activeTab === 'scanner'   && 'LIVE ANALYSIS'}
              {activeTab === 'scans'     && 'THREAT INTELLIGENCE'}
              {activeTab === 'analytics' && 'ANALYTICS'}
              {activeTab === 'models'    && 'AGENTS STATUS'}
            </span>
          </div>

          <div className="top-bar-right">
            {error && (
              <div className="top-error">
                <AlertTriangle size={14} />
                <span>Backend Offline</span>
              </div>
            )}
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              Last sync: {lastUpdate ? lastUpdate.toLocaleTimeString() : '—'}
            </div>
            <button className="refresh-pill" onClick={fetchScans} disabled={loading}>
              <RefreshCw size={13} className={loading ? 'spin' : ''} />
              {loading ? 'Syncing…' : 'Refresh'}
            </button>
            <div className="system-badge">
              <div className="status-dot online" />
              <span>SYSTEM ACTIVE</span>
            </div>
            <div className="admin-badge">
              <div className="admin-info">
                <div className="admin-name">Admin User</div>
                <div className="admin-id">ID: 2202428</div>
              </div>
              <div className="admin-avatar">AD</div>
            </div>
          </div>
        </header>

        {error && (
          <div className="error-banner" role="alert">
            <div className="error-banner-left">
              <AlertTriangle size={16} />
              <div className="error-banner-text">
                <div className="error-banner-title">Request failed</div>
                <div className="error-banner-msg">{error}</div>
              </div>
            </div>
            <button className="error-banner-close" onClick={() => setError(null)} aria-label="Dismiss error">
              <X size={16} />
            </button>
          </div>
        )}

        {/* ══════════════ DASHBOARD TAB ══════════════ */}
        {activeTab === 'dashboard' && (
          <div className="tab-content">
            <div className="page-title">
              <h1>SECURITY OVERVIEW</h1>
              <p>Real-time monitoring of Phish Guard multi-agent defense system.</p>
              <div className="version-tag">v2.4.0 STABLE</div>
            </div>

            {/* Stat cards row */}
            <div className="stat-row">
              {[
                { label: 'URLS SCANNED',      value: totalCount,  icon: Globe,         delta: '+12.5%', color: 'cyan'   },
                { label: 'THREATS BLOCKED',   value: phishCount,  icon: AlertTriangle, delta: '+5.2%',  color: 'orange' },
                { label: 'ACTIVE WHITELIST',  value: legitCount,  icon: CheckCircle,   delta: '+0.8%',  color: 'green'  },
                { label: 'AVG. RESPONSE TIME',value: '0.42s',     icon: Zap,           delta: '-8.1%',  color: 'yellow' },
              ].map((s, i) => (
                <div key={i} className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-label">{s.label}</span>
                    <s.icon size={18} className={`stat-icon ${s.color}`} />
                  </div>
                  <div className="stat-value">{s.value}</div>
                  <div className={`stat-delta ${s.delta.startsWith('+') ? 'up' : 'down'}`}>
                    {s.delta}
                  </div>
                </div>
              ))}
            </div>

            {/* Charts row */}
            <div className="charts-row">
              {/* Traffic analysis */}
              <div className="chart-card wide">
                <div className="card-header">
                  <Activity size={16} className="text-cyan" />
                  <span>TRAFFIC ANALYSIS</span>
                </div>
                <div className="traffic-chart">
                  <svg
                    ref={trafficSvgRef}
                    viewBox="0 0 700 180"
                    preserveAspectRatio="none"
                    className="chart-svg"
                    onMouseLeave={() => setTrafficHoverIdx(null)}
                    onMouseMove={(e) => {
                      const svg = trafficSvgRef.current;
                      if (!svg) return;
                      const rect = svg.getBoundingClientRect();
                      const W = 700;
                      const PAD_L = 18;
                      const PAD_R = 18;
                      const x = ((e.clientX - rect.left) / rect.width) * W;
                      const clamped = Math.max(PAD_L, Math.min(W - PAD_R, x));
                      const ratio = (clamped - PAD_L) / (W - PAD_L - PAD_R);
                      const idx = Math.round(ratio * (24 - 1));
                      setTrafficHoverIdx(Math.max(0, Math.min(23, idx)));
                    }}
                  >
                    {/* Legitimate traffic area */}
                    <defs>
                      <linearGradient id="legitGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.4" />
                        <stop offset="100%" stopColor="#00d4ff" stopOpacity="0.02" />
                      </linearGradient>
                      <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#ff4444" stopOpacity="0.5" />
                        <stop offset="100%" stopColor="#ff4444" stopOpacity="0.02" />
                      </linearGradient>
                    </defs>
                    {/* Filled area for legit */}
                    <path
                      d={legitPaths.area}
                      fill="url(#legitGrad)"
                    />
                    {/* Legit line */}
                    <path
                      d={legitPaths.line}
                      fill="none" stroke="#00d4ff" strokeWidth="2.5"
                    />
                    {/* Phishing area */}
                    <path
                      d={phishPaths.area}
                      fill="url(#phishGrad)"
                    />
                    {/* Phishing line */}
                    <path
                      d={phishPaths.line}
                      fill="none" stroke="#ff4444" strokeWidth="2"
                    />

                    {/* Hover interactions */}
                    {trafficHoverIdx !== null && (() => {
                      const idx = trafficHoverIdx;
                      const x = trafficXForIdx(idx);
                      const legit = traffic.bins[idx]?.legitimate || 0;
                      const phish = traffic.bins[idx]?.phishing || 0;
                      const t = trafficTimeForIdx(idx);
                      const tt = formatTickTime(t);

                      // Y positions (match buildLinePath pads)
                      const H = 180;
                      const PAD_TOP = 18;
                      const PAD_BOTTOM = 22;
                      const usableH = H - PAD_TOP - PAD_BOTTOM;
                      const yLegit = PAD_TOP + (1 - (legit / traffic.maxVal)) * usableH;
                      const yPhish = PAD_TOP + (1 - (phish / traffic.maxVal)) * usableH;

                      // Tooltip positioning
                      const boxW = 156;
                      const boxH = 54;
                      const boxX = Math.max(8, Math.min(700 - boxW - 8, x - boxW / 2));
                      const boxY = 10;

                      return (
                        <g className="traffic-hover">
                          <line x1={x} y1="12" x2={x} y2="160" className="hover-vline" />
                          <circle cx={x} cy={yLegit} r="4.2" className="hover-dot legit" />
                          <circle cx={x} cy={yPhish} r="4.0" className="hover-dot phish" />

                          <g transform={`translate(${boxX},${boxY})`} className="hover-tip">
                            <rect width={boxW} height={boxH} rx="10" ry="10" className="hover-tip-bg" />
                            <text x="12" y="20" className="hover-tip-title">
                              {tt} — last 24h
                            </text>
                            <text x="12" y="38" className="hover-tip-line">
                              Legitimate: <tspan className="tip-cyan">{legit}</tspan>
                            </text>
                            <text x="12" y="52" className="hover-tip-line">
                              Phishing: <tspan className="tip-red">{phish}</tspan>
                            </text>
                          </g>
                        </g>
                      );
                    })()}

                    {/* X-axis labels */}
                    {trafficTickLabels.map((t, i) => {
                      const W = 700;
                      const PAD_L = 18;
                      const PAD_R = 18;
                      const x = PAD_L + (i * (W - PAD_L - PAD_R)) / (trafficTickLabels.length - 1 || 1);
                      return (
                        <text
                          key={`${t}-${i}`}
                          x={x}
                          y="178"
                          fontSize="9"
                          fill="#555"
                          textAnchor="middle"
                        >
                          {t}
                        </text>
                      );
                    })}

                    {/* Transparent overlay to ensure hover works everywhere */}
                    <rect x="0" y="0" width="700" height="180" fill="transparent" />
                  </svg>
                  <div className="chart-legend">
                    <span className="legend-dot cyan" /> Legitimate Traffic
                    <span className="legend-dot red" style={{marginLeft:16}} /> Phishing Attacks
                  </div>
                </div>
              </div>

              {/* Model efficiency */}
              <div className="chart-card">
                <div className="card-header">
                  <Search size={16} className="text-purple" />
                  <span>MODEL EFFICIENCY</span>
                </div>
                <div className="efficiency-bars">
                  {[
                    { label: 'Lexical Analysis',   pct: 94 },
                    { label: 'Semantic Analysis',  pct: 91 },
                    { label: 'HTML Inspection',    pct: 89 },
                    { label: 'Whitelist Filter',   pct: 97 },
                  ].map((m, i) => (
                    <div key={i} className="eff-row">
                      <span className="eff-label">{m.label}</span>
                      <div className="eff-track">
                        <div className="eff-fill" style={{ width: `${m.pct}%`, animationDelay: `${i * 0.15}s` }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent scans table */}
            <div className="table-card">
              <div className="card-header">
                <Clock size={16} className="text-cyan" />
                <span>RECENT DETECTIONS</span>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>TIMESTAMP</th>
                    <th>URL</th>
                    <th>THREAT LEVEL</th>
                    <th>ACTION</th>
                    <th>ANALYSIS AGENT</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 8).map((scan, i) => (
                    <tr key={i} onClick={() => fetchScanDetails(scan)} className="table-row">
                      <td className="ts-cell">
                        {scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td className="url-cell-dark">
                        <Globe size={13} className="text-cyan" style={{marginRight:6,verticalAlign:'middle'}} />
                        {scan.url || 'N/A'}
                      </td>
                      <td>
                        <span className={`threat-badge ${scan.result === 'Phishing' ? 'critical' : 'safe'}`}>
                          {scan.result === 'Phishing' ? 'CRITICAL' : 'SAFE'}
                        </span>
                      </td>
                      <td>
                        <span className={`action-badge ${scan.result === 'Phishing' ? 'blocked' : 'allowed'}`}>
                          {scan.result === 'Phishing' ? 'BLOCKED' : 'ALLOWED'}
                        </span>
                      </td>
                      <td className="agent-cell">
                        {scan.result === 'Phishing'
                          ? (isBlacklistHit(scan) ? 'Blacklist Match' : 'Semantic Analysis')
                          : 'Whitelist Filter'}
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr><td colSpan="5" className="empty-row">No scan data — connect to backend</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══════════════ LIVE ANALYSIS (SCANNER) TAB ══════════════ */}
        {activeTab === 'scanner' && (
          <div className="tab-content">
            <div className="page-title">
              <h1>LIVE ANALYSIS ENGINE</h1>
              <p>Visualizing the four-layered defense funnel in real-time.</p>
            </div>

            {/* URL input bar */}
            <div className="scan-input-card">
              <div className="scan-input-row">
                <div className="scan-input-wrap">
                  <Search size={16} className="scan-input-icon" />
                  <input
                    type="text"
                    placeholder="Enter URL to analyze…  e.g. https://example.com"
                    value={scanUrl}
                    onChange={e => setScanUrl(e.target.value)}
                    onKeyPress={e => e.key === 'Enter' && handleScanUrl()}
                    className="scan-input"
                  />
                </div>
                <button
                  className={`scan-btn ${scanning ? 'scanning' : ''}`}
                  onClick={handleScanUrl}
                  disabled={scanning || !scanUrl.trim()}
                >
                  {scanning ? (
                    <><RefreshCw size={14} className="spin" /> ANALYZING…</>
                  ) : (
                    <><Zap size={14} /> ANALYZE</>
                  )}
                </button>
              </div>
            </div>

            {/* 4-layer funnel diagram */}
            <div className="funnel-layout">
              <div className="funnel-diagram">
                {/* Layer 1 (Highest Priority) */}
                <div className={`funnel-layer ${activeLayer === 0 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title orange">LAYER 1: BLACKLIST</div>
                    <div className="layer-desc">Hard-block match against known malicious URLs stored in the database.</div>
                    <div className="layer-tag">BLOCK BEFORE AI</div>
                  </div>
                  <div className={`layer-node orange ${activeLayer === 0 ? 'pulse' : ''}`}>
                    <Database size={22} />
                  </div>
                  <div className="layer-connector" />
                </div>

                {/* Layer 2 */}
                <div className={`funnel-layer ${activeLayer === 1 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title cyan">LAYER 2: WHITELIST</div>
                    <div className="layer-desc">Rapid verification against known trusted domains.</div>
                    <div className="layer-tag">LATENCY: &lt; 5ms</div>
                  </div>
                  <div className={`layer-node green ${activeLayer === 1 ? 'pulse' : ''}`}>
                    <Lock size={22} />
                  </div>
                  <div className="layer-connector" />
                </div>

                {/* Layer 3 */}
                <div className={`funnel-layer ${activeLayer === 2 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title cyan">LAYER 3: AI ENSEMBLE</div>
                    <div className="layer-desc">6-Model voting system extracting lexical &amp; semantic features.</div>
                    <div className="layer-tag">ACCURACY: 94%</div>
                  </div>
                  <div className={`layer-node blue ${activeLayer === 2 ? 'pulse' : ''}`}>
                    <Cpu size={22} />
                  </div>
                  <div className="layer-connector" />
                </div>

                {/* Layer 4 */}
                <div className={`funnel-layer ${activeLayer === 3 ? 'active' : ''}`} style={{marginBottom:0}}>
                  <div className="layer-info right">
                    <div className="layer-title purple">LAYER 4: CONTENT INSPECTION</div>
                    <div className="layer-desc">Deep scan of DOM elements, hidden fields, and scripts.</div>
                    <div className="layer-tag">ZERO-DAY DETECTION</div>
                  </div>
                  <div className={`layer-node purple-node ${activeLayer === 3 ? 'pulse' : ''}`}>
                    <FileText size={22} />
                  </div>
                </div>
              </div>

              {/* Side panels */}
              <div className="funnel-panels">
                {/* Incoming URL stream */}
                <div className="funnel-panel">
                  <div className="panel-title cyan">Incoming URL Stream</div>
                  {(scans.slice(0, 3).length > 0 ? scans.slice(0, 3) : [
                    { url: 'google.com',             result: 'Legitimate' },
                    { url: 'facebook.com',           result: 'Legitimate' },
                    { url: 'secure-login-attempt.xyz',result: 'Phishing'  },
                  ]).map((s, i) => (
                    <div key={i} className="stream-row">
                      <span className="stream-url">{s.url}</span>
                      {s.result === 'Phishing'
                        ? <ChevronRight size={14} className="text-orange" />
                        : <CheckCircle  size={14} className="text-green"  />
                      }
                    </div>
                  ))}
                </div>

                {/* Multi-agent processing */}
                <div className="funnel-panel">
                  <div className="panel-title cyan">Multi-Agent Processing</div>
                  {['Lexical', 'Semantic'].map((name, i) => (
                    <div key={i} className="agent-bar-row">
                      <span className="agent-bar-label">{name}</span>
                      <div className="agent-bar-track">
                        <div className="agent-bar-fill" style={{ width: `${60 + i * 20}%`, animationDelay: `${i * 0.2}s` }} />
                      </div>
                    </div>
                  ))}
                </div>

                {/* Scan result */}
                {scanResult && (
                  <div className={`funnel-panel result-panel ${scanResult.result === 'Phishing' ? 'danger' : 'success'}`}>
                    <div className="panel-title">
                      {scanResult.result === 'Phishing'
                        ? (isBlacklistHit(scanResult) ? 'Blacklist Match' : 'Deep Analysis Result')
                        : 'Analysis Complete'}
                    </div>
                    <div className={`result-headline ${scanResult.result === 'Phishing' ? 'red' : 'green'}`}>
                      {scanResult.result === 'Phishing' ? (
                        <>
                          <AlertTriangle size={14} /> {isBlacklistHit(scanResult) ? 'BLACKLISTED (BLOCKED)' : 'PHISHING DETECTED'}
                        </>
                      ) : (
                        <><CheckCircle size={14} /> LEGITIMATE URL</>
                      )}
                    </div>
                    <div className="result-url-meta">
                      <span className="meta-label">Link</span>
                      <span className="meta-value">{getUrlMeta(scanResult.url).display}</span>
                    </div>
                    <div className="result-reason">{scanResult.reason}</div>
                    {isBlacklistHit(scanResult) ? (
                      <div className="result-conf">Confidence: 100%</div>
                    ) : scanResult.model_votes ? (
                      <div className="result-conf">
                        Confidence: {Math.round(
                          (Math.max(scanResult.model_votes.phishing_votes, scanResult.model_votes.legitimate_votes)
                          / (scanResult.model_votes.total_votes || 1)) * 100
                        )}%
                      </div>
                    ) : null}

                    {(() => {
                      const eff = getEffectiveness(scanResult);
                      if (!eff) return null;
                      return (
                        <div className={`effectiveness ${eff.tone}`}>
                          <div className="eff-top">
                            <span className="eff-title">{eff.label}</span>
                            <span className="eff-val">{eff.value ? `${eff.value}%` : '—'}</span>
                          </div>
                          <div className="eff-bar">
                            <div className="eff-bar-fill" style={{ width: `${Math.max(0, Math.min(100, eff.value || 0))}%` }} />
                          </div>
                          <div className="eff-hint">{eff.hint}</div>
                        </div>
                      );
                    })()}
                    <button className="clear-btn" onClick={() => { setScanResult(null); setScanUrl(''); }}>
                      Scan Another URL
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════ THREAT INTELLIGENCE (SCAN HISTORY) TAB ══════════════ */}
        {activeTab === 'scans' && (
          <div className="tab-content">
            <div className="page-title">
              <h1>SECURITY OVERVIEW</h1>
              <p>Real-time monitoring of Phish Guard multi-agent defense system.</p>
              <div className="version-tag">v2.4.0 STABLE</div>
            </div>

            {/* Mini stat row */}
            <div className="stat-row" style={{marginBottom: 24}}>
              {[
                { label: 'URLS SCANNED',    value: totalCount, icon: Globe,        color: 'cyan'   },
                { label: 'THREATS BLOCKED', value: phishCount, icon: AlertTriangle, color: 'orange' },
                { label: 'ACTIVE WHITELIST',value: legitCount, icon: CheckCircle,   color: 'green'  },
                { label: 'THREAT RATE',     value: `${stats.phishingRate}%`, icon: Zap, color: 'yellow' },
              ].map((s, i) => (
                <div key={i} className="stat-card">
                  <div className="stat-card-header">
                    <span className="stat-label">{s.label}</span>
                    <s.icon size={18} className={`stat-icon ${s.color}`} />
                  </div>
                  <div className="stat-value">{s.value}</div>
                </div>
              ))}
            </div>

            {/* Search + export bar */}
            <div className="table-card">
              <div className="table-toolbar">
                <div className="search-wrap">
                  <Search size={14} className="search-icon" />
                  <input
                    type="text"
                    placeholder="Search history…"
                    value={searchTerm}
                    onChange={e => setSearchTerm(e.target.value)}
                    className="search-input"
                  />
                </div>
                <button className="export-btn" onClick={downloadCSV} disabled={scans.length === 0}>
                  <Database size={14} /> Export CSV
                </button>
              </div>

              {/* Detections heading */}
              <div className="card-header" style={{marginTop: 8}}>
                <Eye size={16} className="text-cyan" />
                <span>RECENT DETECTIONS</span>
              </div>

              <table className="data-table">
                <thead>
                  <tr>
                    <th>TIMESTAMP</th>
                    <th>URL</th>
                    <th>THREAT LEVEL</th>
                    <th>ACTION</th>
                    <th>ANALYSIS AGENT</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.length === 0 ? (
                    <tr><td colSpan="5" className="empty-row">
                      {searchTerm ? 'No results found' : 'No scans available — start the backend'}
                    </td></tr>
                  ) : filteredScans.map((scan, i) => (
                    <tr key={i} onClick={() => fetchScanDetails(scan)} className="table-row">
                      <td className="ts-cell">
                        {scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString() : 'N/A'}
                      </td>
                      <td className="url-cell-dark">
                        <Globe size={13} className="text-cyan" style={{marginRight:6,verticalAlign:'middle'}} />
                        {scan.url || 'N/A'}
                      </td>
                      <td>
                        <span className={`threat-badge ${scan.result === 'Phishing' ? 'critical' : 'safe'}`}>
                          {scan.result === 'Phishing' ? 'CRITICAL' : 'SAFE'}
                        </span>
                      </td>
                      <td>
                        <span className={`action-badge ${scan.result === 'Phishing' ? 'blocked' : 'allowed'}`}>
                          {scan.result === 'Phishing' ? 'BLOCKED' : 'ALLOWED'}
                        </span>
                      </td>
                      <td className="agent-cell">
                        {scan.result === 'Phishing'
                          ? (isBlacklistHit(scan) ? 'Blacklist Match' : 'Semantic Analysis')
                          : 'Whitelist Filter'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══════════════ ANALYTICS TAB ══════════════ */}
        {activeTab === 'analytics' && (
          <div className="tab-content">
            <div className="page-title">
              <h1>ANALYTICS OVERVIEW</h1>
              <p>Historical performance metrics and detection trends.</p>
            </div>

            <div className="analytics-grid">
              {/* Donut chart */}
              <div className="chart-card">
                <div className="card-header">
                  <BarChart3 size={16} className="text-cyan" /> <span>DETECTION OVERVIEW</span>
                </div>
                <div className="donut-wrap">
                  <svg width="180" height="180" viewBox="0 0 180 180">
                    <circle cx="90" cy="90" r="70" fill="none" stroke="#1a2035" strokeWidth="28" />
                    <circle cx="90" cy="90" r="70" fill="none" stroke="#16a34a"
                      strokeWidth="28"
                      strokeDasharray={`${(stats.legitimateRate / 100) * 440} 440`}
                      transform="rotate(-90 90 90)"
                      style={{transition:'stroke-dasharray 1s ease'}}
                    />
                    <circle cx="90" cy="90" r="70" fill="none" stroke="#dc2626"
                      strokeWidth="28"
                      strokeDasharray={`${(stats.phishingRate / 100) * 440} 440`}
                      strokeDashoffset={`${-(stats.legitimateRate / 100) * 440}`}
                      transform="rotate(-90 90 90)"
                      style={{transition:'stroke-dasharray 1s ease'}}
                    />
                    <text x="90" y="84" textAnchor="middle" fontSize="11" fill="#666" fontWeight="600">Total</text>
                    <text x="90" y="106" textAnchor="middle" fontSize="26" fill="#e2e8f0" fontWeight="700">{stats.total}</text>
                  </svg>
                  <div className="donut-legend">
                    <div><span className="legend-dot green" /> Safe: {stats.legitimateRate}%</div>
                    <div><span className="legend-dot red"   /> Phishing: {stats.phishingRate}%</div>
                  </div>
                </div>
              </div>

              {/* Weekly bar chart */}
              <div className="chart-card wide">
                <div className="card-header">
                  <TrendingUp size={16} className="text-cyan" /> <span>WEEKLY TRENDS</span>
                </div>
                <div className="bar-chart-area">
                  {['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].map((day, i) => {
                    const total = weeklyData[i].legitimate + weeklyData[i].phishing;
                    const lh = (weeklyData[i].legitimate / maxCount) * 140;
                    const ph = (weeklyData[i].phishing   / maxCount) * 140;
                    return (
                      <div key={i} className="bar-col">
                        <div className="bar-stack" style={{height:140}}>
                          <div className="bar-seg legit"  style={{height: lh || 0}} />
                          <div className="bar-seg phish"  style={{height: ph || 0}} />
                        </div>
                        <div className="bar-day">{day}</div>
                        <div className="bar-count">{total}</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Stats grid */}
              <div className="chart-card wide">
                <div className="card-header"><BarChart3 size={16} className="text-cyan" /> <span>DETECTION STATISTICS</span></div>
                <div className="stats-4-grid">
                  {[
                    { label: 'Total Analyzed',    val: stats.total,          color: '#00d4ff' },
                    { label: 'Phishing Detected', val: stats.phishing,       color: '#dc2626' },
                    { label: 'Legitimate URLs',   val: stats.legitimate,     color: '#16a34a' },
                    { label: 'Threat Rate',       val: `${stats.phishingRate}%`, color: '#f59e0b' },
                  ].map((s, i) => (
                    <div key={i} className="stat-mini">
                      <div className="stat-mini-val" style={{color: s.color}}>{s.val}</div>
                      <div className="stat-mini-label">{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════ AGENTS STATUS (AI MODELS) TAB ══════════════ */}
        {activeTab === 'models' && (
          <div className="tab-content">
            <div className="page-title">
              <h1>LIVE ANALYSIS ENGINE</h1>
              <p>Visualizing the four-layered defense funnel in real-time.</p>
            </div>

            <div className="funnel-layout">
              <div className="funnel-diagram">
                <div className={`funnel-layer ${activeLayer === 0 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title orange">LAYER 1: BLACKLIST</div>
                    <div className="layer-desc">Hard-block match against known malicious URLs stored in the database.</div>
                    <div className="layer-tag">BLOCK BEFORE AI</div>
                  </div>
                  <div className={`layer-node orange ${activeLayer === 0 ? 'pulse' : ''}`}><Database size={22} /></div>
                  <div className="layer-connector" />
                </div>
                <div className={`funnel-layer ${activeLayer === 1 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title cyan">LAYER 2: WHITELIST</div>
                    <div className="layer-desc">Rapid verification against known trusted domains.</div>
                    <div className="layer-tag">LATENCY: &lt; 5ms</div>
                  </div>
                  <div className={`layer-node green ${activeLayer === 1 ? 'pulse' : ''}`}><Lock size={22} /></div>
                  <div className="layer-connector" />
                </div>
                <div className={`funnel-layer ${activeLayer === 2 ? 'active' : ''}`}>
                  <div className="layer-info right">
                    <div className="layer-title cyan">LAYER 3: AI ENSEMBLE</div>
                    <div className="layer-desc">6-Model voting system extracting lexical &amp; semantic features.</div>
                    <div className="layer-tag">ACCURACY: 94%</div>
                  </div>
                  <div className={`layer-node blue ${activeLayer === 2 ? 'pulse' : ''}`}><Cpu size={22} /></div>
                  <div className="layer-connector" />
                </div>

                <div className={`funnel-layer ${activeLayer === 3 ? 'active' : ''}`} style={{marginBottom:0}}>
                  <div className="layer-info right">
                    <div className="layer-title purple">LAYER 4: CONTENT INSPECTION</div>
                    <div className="layer-desc">Deep scan of DOM elements, hidden fields, and scripts.</div>
                    <div className="layer-tag">ZERO-DAY DETECTION</div>
                  </div>
                  <div className={`layer-node purple-node ${activeLayer === 3 ? 'pulse' : ''}`}><FileText size={22} /></div>
                </div>
              </div>

              {/* Model cards panel */}
              <div className="funnel-panels">
                <div className="funnel-panel models-panel">
                  <div className="panel-title cyan">AI Model Performance</div>
                  {[
                    { name: 'Random Forest',      acc: '94.2%', team: 'Layer 2 — Ensemble', color: '#00d4ff' },
                    { name: 'LightGBM',           acc: '93.8%', team: 'Layer 2 — Ensemble', color: '#00d4ff' },
                    { name: 'Logistic Regression',acc: '91.5%', team: 'Layer 2 — Scaled',   color: '#16a34a' },
                    { name: 'SVC',                acc: '92.1%', team: 'Layer 2 — Scaled',   color: '#16a34a' },
                    { name: 'XGBoost',            acc: '95.3%', team: 'Layer 2 — TF-IDF',   color: '#f59e0b' },
                    { name: 'Neural Network',     acc: '94.7%', team: 'Layer 2 — TF-IDF',   color: '#f59e0b' },
                  ].map((m, i) => (
                    <div key={i} className="model-row" style={{borderLeftColor: m.color}}>
                      <div>
                        <div className="model-name">{m.name}</div>
                        <div className="model-team">{m.team}</div>
                      </div>
                      <div className="model-acc" style={{color: m.color}}>{m.acc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ══════════════ DETAIL MODAL ══════════════ */}
      {showDetailModal && selectedScan && (
        <div className="modal-overlay" onClick={() => setShowDetailModal(false)}>
          <div className="modal-box" onClick={e => e.stopPropagation()}>
            <ScanLine />

            {/* Modal header */}
            <div className={`modal-header ${selectedScan.result === 'Phishing' ? 'danger' : 'success'}`}>
              <div className="modal-title-row">
                {selectedScan.result === 'Phishing'
                  ? <AlertTriangle size={28} />
                  : <CheckCircle  size={28} />
                }
                <span>
                  {selectedScan.result || 'Unknown'}
                  {isBlacklistHit(selectedScan) ? ' (Blacklisted)' : ''}
                </span>
              </div>
              <p className="modal-subtitle">{selectedScan.reason || 'Analysis complete'}</p>
              <button className="modal-close" onClick={() => setShowDetailModal(false)}>
                <X size={18} />
              </button>
            </div>

            {/* Modal body */}
            <div className="modal-body">
              {detailLoading ? (
                <div className="modal-loading">
                  <RefreshCw size={32} className="spin text-cyan" />
                  <span>Loading details…</span>
                </div>
              ) : (
                <>
                  {/* URL */}
                  <div className="modal-section">
                    <div className="modal-section-title"><Globe size={14} /> Analyzed URL</div>
                    <div className="modal-code">{selectedScan.url || 'N/A'}</div>
                  </div>

                  {/* Model votes */}
                  {selectedScan.model_votes && (
                    <div className="modal-section">
                      <div className="modal-section-title"><BarChart3 size={14} /> AI Models Voting</div>
                      <div className="votes-grid">
                        {[
                          { label: 'Total Votes',    val: selectedScan.model_votes.total_votes,      color: '#00d4ff' },
                          { label: 'Phishing Votes', val: selectedScan.model_votes.phishing_votes,   color: '#dc2626' },
                          { label: 'Safe Votes',     val: selectedScan.model_votes.legitimate_votes, color: '#16a34a' },
                        ].map((v, i) => (
                          <div key={i} className="vote-card" style={{borderColor: v.color}}>
                            <div className="vote-val" style={{color: v.color}}>{v.val || 0}</div>
                            <div className="vote-label">{v.label}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* HTML analysis */}
                  {selectedScan.html_analysis && (
                    <div className="modal-section">
                      <div className="modal-section-title"><Search size={14} /> HTML Content Analysis</div>
                      <div className="html-score-row">
                        <span>Suspicion Score</span>
                        <span style={{color: selectedScan.html_analysis.suspicious ? '#dc2626' : '#16a34a', fontWeight:700}}>
                          {selectedScan.html_analysis.score || 0}/100
                        </span>
                      </div>
                      {selectedScan.html_analysis.evidence?.length > 0 && (
                        <ul className="evidence-list">
                          {selectedScan.html_analysis.evidence.map((e, idx) => (
                            <li key={idx}>{e}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  {/* Timestamp */}
                  <div className="modal-section">
                    <div className="modal-section-title"><Clock size={14} /> Scan Timestamp</div>
                    <div className="modal-ts">
                      {selectedScan.timestamp ? new Date(selectedScan.timestamp).toLocaleString() : 'N/A'}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;