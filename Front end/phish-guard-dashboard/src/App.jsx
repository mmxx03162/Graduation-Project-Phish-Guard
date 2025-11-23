import { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, RefreshCw, TrendingUp, Search, Database, BarChart3, PieChart, Clock, Globe } from 'lucide-react';

function App() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [searchTerm, setSearchTerm] = useState('');

  // URL Scanner state
  const [scanUrl, setScanUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  
  // Detailed View state
  const [selectedScan, setSelectedScan] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);

  // Fetch detailed scan info
  const fetchScanDetails = async (scan) => {
    setDetailLoading(true);
    setSelectedScan(scan);
    setShowDetailModal(true);
    
    // Try to fetch fresh scan data if available
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/scan/?url=${encodeURIComponent(scan.url)}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        mode: 'cors',
      });
      
      if (response.ok) {
        const freshData = await response.json();
        setSelectedScan({...scan, ...freshData});
      }
    } catch (error) {
      console.log('Using existing scan data:', error.message);
    } finally {
      setDetailLoading(false);
    }
  };

  // Fetch logs from Django Backend
  const fetchScans = async () => {
    try {
      setLoading(true);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch('http://127.0.0.1:8000/api/logs/', {
        signal: controller.signal,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        mode: 'cors',
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      const results = data.results || data;
      
      setScans(results);
      setLastUpdate(new Date());
      setError(null);
      setBackendConnected(true);
      
    } catch (err) {
      let errorMessage = 'Cannot connect to backend';
      if (err.name === 'AbortError') {
        errorMessage = 'Connection timeout - Is Django running?';
      } else if (err.message.includes('Failed to fetch')) {
        errorMessage = 'Backend not reachable. Start Django: python manage.py runserver';
      } else {
        errorMessage = err.message;
      }
      setError(errorMessage);
      setBackendConnected(false);
    } finally {
      setLoading(false);
    }
  };

  // Scan URL function
  const handleScanUrl = async () => {
    if (!scanUrl.trim()) {
      alert('Please enter a valid URL');
      return;
    }

    setScanning(true);
    setScanResult(null);
    setError(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: scanUrl }),
        mode: 'cors',
      });

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const data = await response.json();
      setScanResult(data);
      
      // Refresh logs after scan
      await fetchScans();
      
    } catch (err) {
      setError('Scan failed: ' + err.message);
      setScanResult(null);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(() => {
      if (!loading && backendConnected) {
        fetchScans();
      }
    }, 30000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Calculate statistics
  const stats = {
    total: scans.length,
    phishing: scans.filter(s => s.result === 'Phishing').length,
    legitimate: scans.filter(s => s.result === 'Legitimate').length,
    get phishingRate() {
      return this.total > 0 ? ((this.phishing / this.total) * 100).toFixed(1) : 0;
    },
    get legitimateRate() {
      return this.total > 0 ? ((this.legitimate / this.total) * 100).toFixed(1) : 0;
    }
  };

  // Analytics: Group scans by day (last 7 days)
  const getWeeklyStats = () => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const weekData = days.map(() => ({ legitimate: 0, phishing: 0 }));
    
    scans.forEach(scan => {
      if (scan.timestamp) {
        const date = new Date(scan.timestamp);
        const dayIndex = (date.getDay() + 6) % 7; // Convert to Mon=0
        if (scan.result === 'Phishing') {
          weekData[dayIndex].phishing++;
        } else {
          weekData[dayIndex].legitimate++;
        }
      }
    });
    
    return weekData;
  };

  const weeklyData = getWeeklyStats();
  const maxCount = Math.max(...weeklyData.map(d => d.legitimate + d.phishing), 1);

  // Filter scans
  const filteredScans = scans.filter(scan => 
    scan.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    scan.result?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // --- دالة تصدير التقرير لملف إكسيل ---
  const downloadCSV = () => {
    // 1. عناوين الأعمدة
    const headers = ["URL", "Result", "Reason", "Date"];
    
    // 2. تحويل البيانات لنصوص (مع معالجة الفواصل عشان الملف ميبوظش)
    const csvRows = [
      headers.join(','), 
      ...scans.map(scan => {
        const cleanUrl = scan.url ? scan.url.replace(/"/g, '""') : '';
        const cleanReason = scan.reason ? scan.reason.replace(/"/g, '""') : '';
        const date = scan.timestamp ? new Date(scan.timestamp).toLocaleString() : '';
        
        return `"${cleanUrl}","${scan.result}","${cleanReason}","${date}"`;
      })
    ].join('\n');

    // 3. إنشاء رابط التحميل والضغط عليه أوتوماتيكياً
    const blob = new Blob([csvRows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'phish_guard_report.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      {/* Sidebar */}
      <div style={{
        position: 'fixed',
        left: 0,
        top: 0,
        width: '280px',
        height: '100vh',
        background: '#1a1d2e',
        color: 'white',
        padding: '24px 0',
        overflowY: 'auto',
        boxShadow: '4px 0 24px rgba(0,0,0,0.3)',
        zIndex: 100
      }}>
        <div style={{padding: '0 24px', marginBottom: '40px'}}>
          <div style={{display: 'flex', alignItems: 'center', gap: '12px'}}>
            <Shield size={36} color="#00d4ff" />
            <div>
              <h1 style={{margin: 0, fontSize: '24px', fontWeight: '700', color: '#00d4ff'}}>PhishGuard</h1>
              <p style={{margin: 0, fontSize: '12px', color: '#888', fontWeight: '500'}}>AI-Powered Protection</p>
            </div>
          </div>
        </div>

        <nav style={{padding: '0 12px'}}>
          {[
            { id: 'dashboard', icon: Activity, label: 'Dashboard' },
            { id: 'scanner', icon: Search, label: 'URL Scanner' },
            { id: 'scans', icon: Database, label: 'Scan History' },
            { id: 'analytics', icon: BarChart3, label: 'Analytics' },
            { id: 'models', icon: Database, label: 'AI Models' }
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '14px 20px',
                background: activeTab === item.id ? 'rgba(0, 212, 255, 0.15)' : 'transparent',
                border: 'none',
                borderLeft: activeTab === item.id ? '4px solid #00d4ff' : '4px solid transparent',
                color: activeTab === item.id ? '#00d4ff' : '#aaa',
                cursor: 'pointer',
                fontSize: '15px',
                fontWeight: activeTab === item.id ? '600' : '500',
                transition: 'all 0.2s',
                marginBottom: '4px'
              }}
            >
              <item.icon size={20} />
              {item.label}
            </button>
          ))}
        </nav>

        <div style={{
          margin: '40px 24px 0',
          padding: '16px',
          background: backendConnected ? 'rgba(0, 255, 136, 0.1)' : 'rgba(255, 68, 68, 0.1)',
          borderRadius: '12px',
          border: `1px solid ${backendConnected ? 'rgba(0, 255, 136, 0.3)' : 'rgba(255, 68, 68, 0.3)'}`
        }}>
          <div style={{display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px'}}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: backendConnected ? '#00ff88' : '#ff4444',
              boxShadow: `0 0 10px ${backendConnected ? '#00ff88' : '#ff4444'}`
            }} />
            <span style={{fontSize: '13px', fontWeight: '600', color: backendConnected ? '#00ff88' : '#ff4444'}}>
              {backendConnected ? 'Backend Online' : 'Backend Offline'}
            </span>
          </div>
          {lastUpdate && (
            <div style={{fontSize: '11px', color: '#888', display: 'flex', alignItems: 'center', gap: '6px'}}>
              <Clock size={12} />
              {lastUpdate.toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div style={{marginLeft: '280px', padding: '32px', minHeight: '100vh'}}>
        {/* Top Bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '32px'
        }}>
          <div>
            <h2 style={{margin: 0, fontSize: '32px', fontWeight: '700', color: 'white'}}>
              {activeTab === 'dashboard' && 'Security Dashboard'}
              {activeTab === 'scanner' && 'URL Scanner'}
              {activeTab === 'scans' && 'Scan History'}
              {activeTab === 'analytics' && 'Analytics Overview'}
              {activeTab === 'models' && 'AI Detection Models'}
            </h2>
            <p style={{margin: '4px 0 0', color: 'rgba(255,255,255,0.7)', fontSize: '15px'}}>
              Multi-level AI-powered phishing detection system
            </p>
          </div>
          <button
            onClick={fetchScans}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '12px 24px',
              background: loading ? 'rgba(255,255,255,0.1)' : 'white',
              border: 'none',
              borderRadius: '12px',
              color: loading ? 'rgba(255,255,255,0.5)' : '#667eea',
              fontWeight: '600',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: '14px',
              boxShadow: '0 4px 20px rgba(0,0,0,0.2)',
              transition: 'all 0.2s'
            }}
          >
            <RefreshCw size={18} style={{animation: loading ? 'spin 1s linear infinite' : 'none'}} />
            {loading ? 'Refreshing...' : 'Refresh Data'}
          </button>
        </div>

        {/* Error Message */}
        {error && (
          <div style={{
            background: 'rgba(255, 68, 68, 0.1)',
            border: '2px solid rgba(255, 68, 68, 0.3)',
            borderRadius: '12px',
            padding: '16px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <AlertTriangle size={20} color="#ff4444" />
            <span style={{color: '#ff4444', fontSize: '14px', fontWeight: '500'}}>{error}</span>
          </div>
        )}

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '24px',
              marginBottom: '32px'
            }}>
              <div style={{
                background: 'linear-gradient(135deg, #00d4ff 0%, #0099cc 100%)',
                borderRadius: '20px',
                padding: '32px',
                color: 'white',
                boxShadow: '0 8px 32px rgba(0, 212, 255, 0.3)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px'}}>
                  <Database size={32} />
                  <span style={{fontSize: '15px', fontWeight: '600', opacity: 0.9}}>Total Scans</span>
                </div>
                <div style={{fontSize: '56px', fontWeight: '700', marginBottom: '8px'}}>{stats.total}</div>
                <div style={{fontSize: '14px', opacity: 0.8}}>All-time detections</div>
              </div>

              <div style={{
                background: 'linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%)',
                borderRadius: '20px',
                padding: '32px',
                color: 'white',
                boxShadow: '0 8px 32px rgba(255, 107, 107, 0.3)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px'}}>
                  <AlertTriangle size={32} />
                  <span style={{fontSize: '15px', fontWeight: '600', opacity: 0.9}}>Phishing Detected</span>
                </div>
                <div style={{fontSize: '56px', fontWeight: '700', marginBottom: '8px'}}>{stats.phishing}</div>
                <div style={{fontSize: '14px', opacity: 0.8}}>{stats.phishingRate}% of total</div>
              </div>

              <div style={{
                background: 'linear-gradient(135deg, #51cf66 0%, #37b24d 100%)',
                borderRadius: '20px',
                padding: '32px',
                color: 'white',
                boxShadow: '0 8px 32px rgba(81, 207, 102, 0.3)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px'}}>
                  <CheckCircle size={32} />
                  <span style={{fontSize: '15px', fontWeight: '600', opacity: 0.9}}>Safe URLs</span>
                </div>
                <div style={{fontSize: '56px', fontWeight: '700', marginBottom: '8px'}}>{stats.legitimate}</div>
                <div style={{fontSize: '14px', opacity: 0.8}}>{stats.legitimateRate}% verified safe</div>
              </div>
            </div>

            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '24px',
              marginBottom: '32px'
            }}>
              <div style={{
                background: 'white',
                borderRadius: '20px',
                padding: '32px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px'}}>
                  <PieChart size={24} color="#667eea" />
                  <h3 style={{margin: 0, fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>Detection Rate</h3>
                </div>
                <div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '280px'}}>
                  <svg width="240" height="240" viewBox="0 0 240 240">
                    <circle cx="120" cy="120" r="100" fill="none" stroke="#f0f0f0" strokeWidth="40" />
                    <circle
                      cx="120"
                      cy="120"
                      r="100"
                      fill="none"
                      stroke="#51cf66"
                      strokeWidth="40"
                      strokeDasharray={`${(stats.legitimateRate / 100) * 628} 628`}
                      transform="rotate(-90 120 120)"
                    />
                    <circle
                      cx="120"
                      cy="120"
                      r="100"
                      fill="none"
                      stroke="#ff6b6b"
                      strokeWidth="40"
                      strokeDasharray={`${(stats.phishingRate / 100) * 628} 628`}
                      strokeDashoffset={`${-(stats.legitimateRate / 100) * 628}`}
                      transform="rotate(-90 120 120)"
                    />
                    <text x="120" y="110" textAnchor="middle" fontSize="16" fill="#888" fontWeight="600">Detection</text>
                    <text x="120" y="140" textAnchor="middle" fontSize="36" fill="#1a1d2e" fontWeight="700">{stats.total}</text>
                  </svg>
                </div>
                <div style={{display: 'flex', justifyContent: 'center', gap: '32px', marginTop: '20px'}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                    <div style={{width: '14px', height: '14px', borderRadius: '3px', background: '#51cf66'}} />
                    <span style={{fontSize: '15px', color: '#555', fontWeight: '600'}}>Safe: {stats.legitimateRate}%</span>
                  </div>
                  <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                    <div style={{width: '14px', height: '14px', borderRadius: '3px', background: '#ff6b6b'}} />
                    <span style={{fontSize: '15px', color: '#555', fontWeight: '600'}}>Phishing: {stats.phishingRate}%</span>
                  </div>
                </div>
              </div>

              <div style={{
                background: 'white',
                borderRadius: '20px',
                padding: '32px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px'}}>
                  <TrendingUp size={24} color="#667eea" />
                  <h3 style={{margin: 0, fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>Weekly Activity</h3>
                </div>
                <div style={{height: '280px', display: 'flex', alignItems: 'flex-end', gap: '16px', padding: '20px 0'}}>
                  {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, i) => {
                    const total = weeklyData[i].legitimate + weeklyData[i].phishing;
                    const legitHeight = (weeklyData[i].legitimate / maxCount) * 100;
                    const phishHeight = (weeklyData[i].phishing / maxCount) * 100;
                    
                    return (
                      <div key={i} style={{flex: 1, display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'center'}}>
                        <div style={{width: '100%', height: '200px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: '2px'}}>
                      <div style={{
                            height: `${legitHeight}%`,
                            background: 'linear-gradient(180deg, #51cf66 0%, #37b24d 100%)',
                            borderRadius: '6px 6px 0 0',
                            minHeight: weeklyData[i].legitimate > 0 ? '8px' : '0'
                          }} />
                      <div style={{
                            height: `${phishHeight}%`,
                            background: 'linear-gradient(180deg, #ff6b6b 0%, #ee5a52 100%)',
                            borderRadius: '6px 6px 0 0',
                            minHeight: weeklyData[i].phishing > 0 ? '8px' : '0'
                          }} />
                    </div>
                        <span style={{fontSize: '12px', color: '#888', fontWeight: '600', marginTop: '8px'}}>{day}</span>
                        <span style={{fontSize: '11px', color: '#aaa', fontWeight: '500'}}>{total}</span>
                </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div style={{
              background: 'white',
              borderRadius: '20px',
              padding: '32px',
              boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
            }}>
              <h3 style={{margin: '0 0 20px', fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>Recent Scans</h3>
              <div style={{overflowX: 'auto'}}>
                <table style={{width: '100%', borderCollapse: 'collapse'}}>
                  <thead>
                    <tr style={{background: '#f8f9fa', borderBottom: '2px solid #e9ecef'}}>
                      <th style={{padding: '16px', textAlign: 'left', fontWeight: '600', color: '#495057', fontSize: '14px'}}>URL</th>
                      <th style={{padding: '16px', textAlign: 'center', fontWeight: '600', color: '#495057', fontSize: '14px'}}>Result</th>
                      <th style={{padding: '16px', textAlign: 'left', fontWeight: '600', color: '#495057', fontSize: '14px'}}>Reason</th>
                      <th style={{padding: '16px', textAlign: 'center', fontWeight: '600', color: '#495057', fontSize: '14px'}}>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.slice(0, 5).map((scan, i) => (
                      <tr key={i} style={{borderBottom: '1px solid #f0f0f0', cursor: 'pointer'}} onClick={() => fetchScanDetails(scan)}>
                        <td style={{padding: '16px', fontSize: '14px', color: '#212529', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                          <Globe size={16} color="#667eea" style={{display: 'inline-block', marginRight: '8px', verticalAlign: 'middle'}} />
                          <span style={{color: '#667eea', textDecoration: 'underline'}}>{scan.url || 'N/A'}</span>
                        </td>
                        <td style={{padding: '16px', textAlign: 'center'}}>
                          <span style={{
                            padding: '6px 20px',
                            borderRadius: '20px',
                            fontSize: '13px',
                            fontWeight: '600',
                            background: scan.result === 'Phishing' ? '#ffe3e3' : '#d4f4dd',
                            color: scan.result === 'Phishing' ? '#ff4444' : '#00aa44'
                          }}>
                            {scan.result || 'Unknown'}
                          </span>
                        </td>
                        <td style={{padding: '16px', fontSize: '13px', color: '#666', maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                          {scan.reason || 'No reason provided'}
                        </td>
                        <td style={{padding: '16px', textAlign: 'center', fontSize: '13px', color: '#6c757d'}}>
                          {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* URL Scanner Tab */}
        {activeTab === 'scanner' && (
          <div style={{maxWidth: '1200px', margin: '0 auto'}}>
            <div style={{
              background: 'white',
              borderRadius: '20px',
              padding: '40px',
              boxShadow: '0 8px 32px rgba(0,0,0,0.15)',
              marginBottom: '32px'
            }}>
              <div style={{textAlign: 'center', marginBottom: '32px'}}>
                <Search size={64} color="#667eea" style={{marginBottom: '16px'}} />
                <h3 style={{margin: '0 0 8px', fontSize: '28px', fontWeight: '700', color: '#1a1d2e'}}>Analyze URL</h3>
                <p style={{margin: 0, fontSize: '15px', color: '#888'}}>Enter a URL to detect if it's phishing or legitimate</p>
              </div>

              <div style={{display: 'flex', gap: '12px', marginBottom: '24px'}}>
                <input
                  type="text"
                  placeholder="https://example.com"
                  value={scanUrl}
                  onChange={(e) => setScanUrl(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleScanUrl()}
                  style={{
                    flex: 1,
                    padding: '18px 24px',
                    border: '2px solid #e9ecef',
                    borderRadius: '12px',
                    fontSize: '16px',
                    outline: 'none',
                    transition: 'all 0.2s'
                  }}
                />
                <button
                  onClick={handleScanUrl}
                  disabled={scanning || !scanUrl.trim()}
                  style={{
                    padding: '18px 48px',
                    background: scanning ? '#ccc' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    border: 'none',
                    borderRadius: '12px',
                    color: 'white',
                    fontSize: '16px',
                    fontWeight: '600',
                    cursor: scanning || !scanUrl.trim() ? 'not-allowed' : 'pointer',
                    boxShadow: '0 4px 20px rgba(102, 126, 234, 0.4)',
                    transition: 'all 0.2s'
                  }}
                >
                  {scanning ? 'Analyzing...' : 'Analyze'}
                </button>
              </div>
            </div>

            {scanResult && (
              <div style={{
                background: 'white',
                borderRadius: '20px',
                padding: '40px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
              }}>
                <div style={{
                  textAlign: 'center',
                  padding: '32px',
                  background: scanResult.result === 'Phishing' ? 
                    'linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%)' : 
                    'linear-gradient(135deg, #51cf66 0%, #37b24d 100%)',
                  borderRadius: '16px',
                  color: 'white',
                  marginBottom: '32px'
                }}>
                  {scanResult.result === 'Phishing' ? (
                    <AlertTriangle size={72} style={{marginBottom: '16px'}} />
                  ) : (
                    <CheckCircle size={72} style={{marginBottom: '16px'}} />
                  )}
                  <h2 style={{margin: '0 0 8px', fontSize: '36px', fontWeight: '700'}}>
                    {scanResult.result || 'Unknown'}
                  </h2>
                  <p style={{margin: 0, fontSize: '16px', opacity: 0.9}}>
                    {scanResult.reason || 'Analysis completed'}
                  </p>
                </div>

                {/* Detailed Reason Section */}
                {scanResult.reason && (
                  <div style={{
                    background: 'white',
                    borderRadius: '16px',
                    padding: '32px',
                    marginBottom: '32px',
                    border: '2px solid #e9ecef',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.1)'
                  }}>
                    <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px'}}>
                      <AlertTriangle size={24} color={scanResult.result === 'Phishing' ? '#ff4444' : '#00aa44'} />
                      <h3 style={{margin: 0, fontSize: '22px', fontWeight: '700', color: '#1a1d2e'}}>
                        Detailed Analysis Reason
                      </h3>
                    </div>
                    <div style={{
                      padding: '20px',
                      background: scanResult.result === 'Phishing' ? '#fff5f5' : '#f0fdf4',
                      borderRadius: '12px',
                      borderLeft: `4px solid ${scanResult.result === 'Phishing' ? '#ff4444' : '#00aa44'}`,
                      fontSize: '15px',
                      lineHeight: '1.8',
                      color: '#333'
                    }}>
                      {scanResult.reason}
                    </div>
                  </div>
                )}

                {scanResult.model_votes && (
                  <div style={{marginBottom: '32px'}}>
                    <h3 style={{margin: '0 0 20px', fontSize: '22px', fontWeight: '700', color: '#1a1d2e', display: 'flex', alignItems: 'center', gap: '12px'}}>
                      <BarChart3 size={24} color="#667eea" />
                      Model Votes
                    </h3>
                    
                    {/* Pie Chart Section */}
                    <div style={{
                      display: 'flex',
                      justifyContent: 'center',
                      marginBottom: '24px'
                    }}>
                      {/* Pie Chart */}
                      <div style={{
                        background: '#f8f9fa',
                        borderRadius: '16px',
                        padding: '32px',
                        textAlign: 'center',
                        maxWidth: '500px',
                        width: '100%'
                      }}>
                        <h4 style={{margin: '0 0 24px', fontSize: '18px', fontWeight: '700', color: '#1a1d2e'}}>
                          Models Distribution
                        </h4>
                        <div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', marginBottom: '24px'}}>
                          <svg width="280" height="280" viewBox="0 0 280 280">
                            {/* Background circle */}
                            <circle cx="140" cy="140" r="110" fill="none" stroke="#f0f0f0" strokeWidth="50" />
                            
                            {/* Phishing votes circle */}
                            {(scanResult.model_votes.phishing_votes || 0) > 0 && (
                              <circle
                                cx="140"
                                cy="140"
                                r="110"
                                fill="none"
                                stroke="#ff6b6b"
                                strokeWidth="50"
                                strokeDasharray={`${((scanResult.model_votes.phishing_votes || 0) / (scanResult.model_votes.total_votes || 1)) * 690} 690`}
                                transform="rotate(-90 140 140)"
                              />
                            )}
                            
                            {/* Safe votes circle */}
                            {(scanResult.model_votes.legitimate_votes || 0) > 0 && (
                              <circle
                                cx="140"
                                cy="140"
                                r="110"
                                fill="none"
                                stroke="#51cf66"
                                strokeWidth="50"
                                strokeDasharray={`${((scanResult.model_votes.legitimate_votes || 0) / (scanResult.model_votes.total_votes || 1)) * 690} 690`}
                                strokeDashoffset={`${-((scanResult.model_votes.phishing_votes || 0) / (scanResult.model_votes.total_votes || 1)) * 690}`}
                                transform="rotate(-90 140 140)"
                              />
                            )}
                            
                            {/* Center text */}
                            <text x="140" y="130" textAnchor="middle" fontSize="16" fill="#888" fontWeight="600">
                              {scanResult.model_votes.total_votes || 0} Models
                            </text>
                            <text x="140" y="155" textAnchor="middle" fontSize="32" fill="#1a1d2e" fontWeight="700">
                              {scanResult.model_votes.phishing_votes >= scanResult.model_votes.legitimate_votes ? 
                                Math.round((scanResult.model_votes.phishing_votes / (scanResult.model_votes.total_votes || 1)) * 100) :
                                Math.round((scanResult.model_votes.legitimate_votes / (scanResult.model_votes.total_votes || 1)) * 100)
                              }%
                            </text>
                          </svg>
                        </div>
                        <div style={{display: 'flex', justifyContent: 'center', gap: '32px'}}>
                          <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                            <div style={{width: '16px', height: '16px', borderRadius: '4px', background: '#51cf66'}} />
                            <span style={{fontSize: '14px', color: '#555', fontWeight: '600'}}>
                              Safe: {Math.round((scanResult.model_votes.legitimate_votes / (scanResult.model_votes.total_votes || 1)) * 100)}%
                            </span>
                          </div>
                          <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                            <div style={{width: '16px', height: '16px', borderRadius: '4px', background: '#ff6b6b'}} />
                            <span style={{fontSize: '14px', color: '#555', fontWeight: '600'}}>
                              Phishing: {Math.round((scanResult.model_votes.phishing_votes / (scanResult.model_votes.total_votes || 1)) * 100)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Summary Cards */}
                    <div style={{
                      padding: '24px',
                      background: '#f8f9fa',
                      borderRadius: '12px'
                    }}>
                      <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px'}}>
                        <div style={{textAlign: 'center', padding: '16px', background: 'white', borderRadius: '8px'}}>
                          <div style={{fontSize: '32px', fontWeight: '700', color: '#00d4ff', marginBottom: '4px'}}>
                            {scanResult.model_votes.total_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Total Votes</div>
                        </div>
                        <div style={{textAlign: 'center', padding: '16px', background: 'white', borderRadius: '8px'}}>
                          <div style={{fontSize: '32px', fontWeight: '700', color: '#ff4444', marginBottom: '4px'}}>
                            {scanResult.model_votes.phishing_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Phishing Votes</div>
                        </div>
                        <div style={{textAlign: 'center', padding: '16px', background: 'white', borderRadius: '8px'}}>
                          <div style={{fontSize: '32px', fontWeight: '700', color: '#00aa44', marginBottom: '4px'}}>
                            {scanResult.model_votes.legitimate_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Safe Votes</div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div style={{
                  padding: '24px',
                  background: '#f8f9fa',
                  borderRadius: '12px',
                  marginBottom: '24px'
                }}>
                  <h4 style={{margin: '0 0 16px', fontSize: '18px', fontWeight: '700', color: '#1a1d2e', display: 'flex', alignItems: 'center', gap: '8px'}}>
                    <Globe size={20} color="#667eea" />
                    Analyzed URL
                  </h4>
                  <div style={{
                    padding: '16px',
                    background: 'white',
                    borderRadius: '8px',
                    fontSize: '14px',
                    color: '#495057',
                    wordBreak: 'break-all',
                    border: '1px solid #dee2e6'
                  }}>
                    {scanResult.url || scanUrl}
                  </div>
                </div>

                <button
                  onClick={() => {
                    setScanResult(null);
                    setScanUrl('');
                  }}
                  style={{
                    width: '100%',
                    padding: '16px',
                    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                    border: 'none',
                    borderRadius: '12px',
                    color: 'white',
                    fontSize: '16px',
                    fontWeight: '600',
                    cursor: 'pointer',
                    boxShadow: '0 4px 20px rgba(102, 126, 234, 0.4)'
                  }}
                >
                  Scan Another URL
                </button>
              </div>
            )}
          </div>
        )}

        {/* Scan History Tab */}
        {activeTab === 'scans' && (
          <div style={{
            background: 'white',
            borderRadius: '20px',
            padding: '28px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
          }}>
            {/* الشريط العلوي: بحث + زرار التصدير */}
            <div style={{marginBottom: '24px', display: 'flex', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap'}}>
              
              {/* مربع البحث (زي ما هو) */}
              <div style={{position: 'relative', flex: 1, minWidth: '200px'}}>
                <Search size={20} color="#888" style={{position: 'absolute', left: '16px', top: '50%', transform: 'translateY(-50%)'}} />
                <input
                  type="text"
                  placeholder="Search history..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '14px 16px 14px 48px',
                    border: '2px solid #e9ecef',
                    borderRadius: '12px',
                    fontSize: '15px',
                    outline: 'none',
                    transition: 'all 0.2s'
                  }}
                />
              </div>

              {/* --- زرار التصدير الجديد --- */}
              <button
                onClick={downloadCSV}
                disabled={scans.length === 0}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '14px 24px',
                  background: scans.length === 0 ? '#ccc' : '#10b981', // لون أخضر مميز
                  color: 'white',
                  border: 'none',
                  borderRadius: '12px',
                  cursor: scans.length === 0 ? 'not-allowed' : 'pointer',
                  fontWeight: '600',
                  fontSize: '14px',
                  boxShadow: scans.length === 0 ? 'none' : '0 4px 15px rgba(16, 185, 129, 0.3)',
                  transition: 'transform 0.2s'
                }}
                onMouseOver={(e) => {
                  if (scans.length > 0) {
                    e.currentTarget.style.transform = 'translateY(-2px)';
                    e.currentTarget.style.boxShadow = '0 6px 20px rgba(16, 185, 129, 0.4)';
                  }
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  if (scans.length > 0) {
                    e.currentTarget.style.boxShadow = '0 4px 15px rgba(16, 185, 129, 0.3)';
                  }
                }}
              >
                <Database size={18} /> Export CSV
              </button>

            </div>

            <div style={{overflowX: 'auto'}}>
              <table style={{width: '100%', borderCollapse: 'collapse'}}>
                <thead>
                  <tr style={{background: '#f8f9fa', borderBottom: '2px solid #e9ecef'}}>
                    <th style={{padding: '16px', textAlign: 'left', fontWeight: '600', color: '#495057', fontSize: '13px'}}>URL</th>
                    <th style={{padding: '16px', textAlign: 'center', fontWeight: '600', color: '#495057', fontSize: '13px'}}>Result</th>
                    <th style={{padding: '16px', textAlign: 'left', fontWeight: '600', color: '#495057', fontSize: '13px'}}>Reason</th>
                    <th style={{padding: '16px', textAlign: 'center', fontWeight: '600', color: '#495057', fontSize: '13px'}}>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.length === 0 ? (
                    <tr>
                      <td colSpan="4" style={{padding: '40px', textAlign: 'center', color: '#888', fontSize: '15px'}}>
                        {searchTerm ? 'No results found' : 'No scans available'}
                      </td>
                    </tr>
                  ) : (
                    filteredScans.map((scan, i) => (
                    <tr key={i} style={{borderBottom: '1px solid #f0f0f0', cursor: 'pointer'}} onClick={() => fetchScanDetails(scan)}>
                        <td style={{padding: '16px', fontSize: '14px', color: '#212529', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                        <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                          <Globe size={16} color="#667eea" />
                            <span style={{color: '#667eea', textDecoration: 'underline'}}>
                          {scan.url || 'N/A'}
                            </span>
                        </div>
                      </td>
                      <td style={{padding: '16px', textAlign: 'center'}}>
                        <span style={{
                          padding: '6px 16px',
                          borderRadius: '20px',
                          fontSize: '13px',
                          fontWeight: '600',
                          background: scan.result === 'Phishing' ? '#ffe3e3' : '#d4f4dd',
                          color: scan.result === 'Phishing' ? '#ff4444' : '#00aa44'
                        }}>
                          {scan.result || 'Unknown'}
                        </span>
                      </td>
                        <td style={{padding: '16px', fontSize: '13px', color: '#666', maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                          {scan.reason || 'No reason provided'}
                      </td>
                      <td style={{padding: '16px', textAlign: 'center', fontSize: '13px', color: '#6c757d'}}>
                        {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : 'N/A'}
                      </td>
                    </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Analytics Tab */}
        {activeTab === 'analytics' && (
          <div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: '24px',
              marginBottom: '32px'
            }}>
              <div style={{
                background: 'white',
                borderRadius: '20px',
                padding: '32px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px'}}>
                  <PieChart size={24} color="#667eea" />
                  <h3 style={{margin: 0, fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>Detection Overview</h3>
                </div>
                <div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '240px'}}>
                  <svg width="200" height="200" viewBox="0 0 200 200">
                    <circle cx="100" cy="100" r="80" fill="none" stroke="#f0f0f0" strokeWidth="32" />
                    <circle
                      cx="100"
                      cy="100"
                      r="80"
                      fill="none"
                      stroke="#51cf66"
                      strokeWidth="32"
                      strokeDasharray={`${(stats.legitimateRate / 100) * 502} 502`}
                      transform="rotate(-90 100 100)"
                    />
                    <circle
                      cx="100"
                      cy="100"
                      r="80"
                      fill="none"
                      stroke="#ff6b6b"
                      strokeWidth="32"
                      strokeDasharray={`${(stats.phishingRate / 100) * 502} 502`}
                      strokeDashoffset={`${-(stats.legitimateRate / 100) * 502}`}
                      transform="rotate(-90 100 100)"
                    />
                    <text x="100" y="95" textAnchor="middle" fontSize="14" fill="#888" fontWeight="600">Total</text>
                    <text x="100" y="120" textAnchor="middle" fontSize="32" fill="#1a1d2e" fontWeight="700">{stats.total}</text>
                  </svg>
                </div>
              </div>

              <div style={{
                background: 'white',
                borderRadius: '20px',
                padding: '32px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
              }}>
                <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px'}}>
                  <TrendingUp size={24} color="#667eea" />
                  <h3 style={{margin: 0, fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>Weekly Trends</h3>
                </div>
                <div style={{height: '240px', display: 'flex', alignItems: 'flex-end', gap: '12px', padding: '20px 0'}}>
                  {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, i) => {
                    const total = weeklyData[i].legitimate + weeklyData[i].phishing;
                    const height = (total / maxCount) * 100;
                    
                    return (
                      <div key={i} style={{flex: 1, display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'center'}}>
                        <div style={{
                          width: '100%',
                          height: '180px',
                          display: 'flex',
                          alignItems: 'flex-end',
                          justifyContent: 'center'
                        }}>
                          <div style={{
                            width: '100%',
                            height: `${height}%`,
                            background: 'linear-gradient(180deg, #667eea 0%, #764ba2 100%)',
                            borderRadius: '8px 8px 0 0',
                            minHeight: total > 0 ? '12px' : '0'
                          }} />
                        </div>
                        <span style={{fontSize: '11px', color: '#888', fontWeight: '600', marginTop: '8px'}}>{day}</span>
                        <span style={{fontSize: '10px', color: '#aaa', fontWeight: '500'}}>{total}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div style={{
              background: 'white',
              borderRadius: '20px',
              padding: '32px',
              boxShadow: '0 8px 32px rgba(0,0,0,0.15)'
            }}>
              <h3 style={{margin: '0 0 24px', fontSize: '20px', fontWeight: '700', color: '#1a1d2e'}}>
                Detection Statistics
              </h3>
              <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px'}}>
                <div style={{padding: '20px', background: '#f8f9fa', borderRadius: '12px', textAlign: 'center'}}>
                  <div style={{fontSize: '36px', fontWeight: '700', color: '#00d4ff', marginBottom: '8px'}}>
                    {stats.total}
                  </div>
                  <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Total Analyzed</div>
                </div>
                <div style={{padding: '20px', background: '#ffe3e3', borderRadius: '12px', textAlign: 'center'}}>
                  <div style={{fontSize: '36px', fontWeight: '700', color: '#ff4444', marginBottom: '8px'}}>
                    {stats.phishing}
                  </div>
                  <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Phishing Detected</div>
                </div>
                <div style={{padding: '20px', background: '#d4f4dd', borderRadius: '12px', textAlign: 'center'}}>
                  <div style={{fontSize: '36px', fontWeight: '700', color: '#00aa44', marginBottom: '8px'}}>
                    {stats.legitimate}
                  </div>
                  <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Legitimate URLs</div>
                </div>
                <div style={{padding: '20px', background: '#fff3e0', borderRadius: '12px', textAlign: 'center'}}>
                  <div style={{fontSize: '36px', fontWeight: '700', color: '#ff9800', marginBottom: '8px'}}>
                    {stats.phishingRate}%
                  </div>
                  <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Threat Rate</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* AI Models Tab */}
        {activeTab === 'models' && (
          <div style={{display: 'grid', gap: '24px'}}>
            {[
              {name: 'Random Forest', accuracy: '94.2%', team: 'Numerical Features', color: '#00d4ff'},
              {name: 'LightGBM', accuracy: '93.8%', team: 'Numerical Features', color: '#00d4ff'},
              {name: 'Logistic Regression', accuracy: '91.5%', team: 'Scaled Features', color: '#51cf66'},
              {name: 'SVC', accuracy: '92.1%', team: 'Scaled Features', color: '#51cf66'},
              {name: 'XGBoost', accuracy: '95.3%', team: 'TF-IDF + Numerical', color: '#ff6b6b'},
              {name: 'Neural Network', accuracy: '94.7%', team: 'TF-IDF + Numerical', color: '#ff6b6b'}
            ].map((model, i) => (
              <div key={i} style={{
                background: 'white',
                borderRadius: '20px',
                padding: '28px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.15)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderLeft: `6px solid ${model.color}`
              }}>
                <div>
                  <h3 style={{margin: '0 0 8px', fontSize: '22px', fontWeight: '700', color: '#1a1d2e'}}>{model.name}</h3>
                  <p style={{margin: 0, fontSize: '14px', color: '#888'}}>{model.team}</p>
                </div>
                <div style={{
                  fontSize: '32px',
                  fontWeight: '700',
                  color: model.color
                }}>
                  {model.accuracy}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Detailed Analysis Modal */}
      {showDetailModal && selectedScan && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 1000,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '20px',
          overflowY: 'auto'
        }} onClick={() => setShowDetailModal(false)}>
          <div style={{
            background: 'white',
            borderRadius: '24px',
            maxWidth: '1200px',
            width: '100%',
            maxHeight: '90vh',
            overflowY: 'auto',
            boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
            position: 'relative'
          }} onClick={(e) => e.stopPropagation()}>
            {/* Header */}
            <div style={{
              padding: '32px',
              background: selectedScan.result === 'Phishing' ? 
                'linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%)' : 
                'linear-gradient(135deg, #51cf66 0%, #37b24d 100%)',
              borderRadius: '24px 24px 0 0',
              color: 'white',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <div style={{flex: 1}}>
                <div style={{display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '12px'}}>
                  {selectedScan.result === 'Phishing' ? (
                    <AlertTriangle size={48} />
                  ) : (
                    <CheckCircle size={48} />
                  )}
                  <h2 style={{margin: 0, fontSize: '32px', fontWeight: '700'}}>
                    {selectedScan.result || 'Unknown'}
                  </h2>
                </div>
                <p style={{margin: 0, fontSize: '16px', opacity: 0.9}}>
                  {selectedScan.reason || 'Analysis completed'}
                </p>
              </div>
              <button
                onClick={() => setShowDetailModal(false)}
                style={{
                  background: 'rgba(255,255,255,0.2)',
                  border: 'none',
                  borderRadius: '50%',
                  width: '40px',
                  height: '40px',
                  color: 'white',
                  cursor: 'pointer',
                  fontSize: '24px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                ×
              </button>
            </div>

            {/* Content */}
            <div style={{padding: '32px'}}>
              {detailLoading ? (
                <div style={{textAlign: 'center', padding: '60px'}}>
                  <RefreshCw size={48} style={{animation: 'spin 1s linear infinite'}} />
                  <p style={{marginTop: '20px', color: '#666'}}>Loading details...</p>
                </div>
              ) : (
                <>
                  {/* URL Section */}
                  <div style={{
                    background: '#f8f9fa',
                    borderRadius: '16px',
                    padding: '24px',
                    marginBottom: '24px',
                    border: '2px solid #e9ecef'
                  }}>
                    <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px'}}>
                      <Globe size={24} color="#667eea" />
                      <h3 style={{margin: 0, fontSize: '18px', fontWeight: '700', color: '#1a1d2e'}}>
                        Analyzed URL
                      </h3>
                    </div>
                    <div style={{
                      padding: '16px',
                      background: 'white',
                      borderRadius: '8px',
                      fontSize: '14px',
                      color: '#495057',
                      wordBreak: 'break-all',
                      fontFamily: 'monospace'
                    }}>
                      {selectedScan.url || 'N/A'}
                    </div>
                  </div>

                  {/* Model Votes Section */}
                  {selectedScan.model_votes && (
                    <div style={{
                      background: '#f8f9fa',
                      borderRadius: '16px',
                      padding: '24px',
                      marginBottom: '24px'
                    }}>
                      <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px'}}>
                        <BarChart3 size={24} color="#667eea" />
                        <h3 style={{margin: 0, fontSize: '18px', fontWeight: '700', color: '#1a1d2e'}}>
                          AI Models Voting Results
                        </h3>
                      </div>

                      {/* Pie Chart Section */}
                      <div style={{
                        display: 'flex',
                        justifyContent: 'center',
                        marginBottom: '24px'
                      }}>
                        {/* Pie Chart */}
                        <div style={{
                          background: 'white',
                          borderRadius: '16px',
                          padding: '32px',
                          textAlign: 'center',
                          maxWidth: '500px',
                          width: '100%'
                        }}>
                          <h4 style={{margin: '0 0 24px', fontSize: '18px', fontWeight: '700', color: '#1a1d2e'}}>
                            Models Distribution
                          </h4>
                          <div style={{display: 'flex', justifyContent: 'center', alignItems: 'center', marginBottom: '24px'}}>
                            <svg width="280" height="280" viewBox="0 0 280 280">
                              {/* Background circle */}
                              <circle cx="140" cy="140" r="110" fill="none" stroke="#f0f0f0" strokeWidth="50" />
                              
                              {/* Phishing votes circle */}
                              {(selectedScan.model_votes.phishing_votes || 0) > 0 && (
                                <circle
                                  cx="140"
                                  cy="140"
                                  r="110"
                                  fill="none"
                                  stroke="#ff6b6b"
                                  strokeWidth="50"
                                  strokeDasharray={`${((selectedScan.model_votes.phishing_votes || 0) / (selectedScan.model_votes.total_votes || 1)) * 690} 690`}
                                  transform="rotate(-90 140 140)"
                                />
                              )}
                              
                              {/* Safe votes circle */}
                              {(selectedScan.model_votes.legitimate_votes || 0) > 0 && (
                                <circle
                                  cx="140"
                                  cy="140"
                                  r="110"
                                  fill="none"
                                  stroke="#51cf66"
                                  strokeWidth="50"
                                  strokeDasharray={`${((selectedScan.model_votes.legitimate_votes || 0) / (selectedScan.model_votes.total_votes || 1)) * 690} 690`}
                                  strokeDashoffset={`${-((selectedScan.model_votes.phishing_votes || 0) / (selectedScan.model_votes.total_votes || 1)) * 690}`}
                                  transform="rotate(-90 140 140)"
                                />
                              )}
                              
                              {/* Center text */}
                              <text x="140" y="130" textAnchor="middle" fontSize="16" fill="#888" fontWeight="600">
                                {selectedScan.model_votes.total_votes || 0} Models
                              </text>
                              <text x="140" y="155" textAnchor="middle" fontSize="32" fill="#1a1d2e" fontWeight="700">
                                {selectedScan.model_votes.phishing_votes >= selectedScan.model_votes.legitimate_votes ? 
                                  Math.round((selectedScan.model_votes.phishing_votes / (selectedScan.model_votes.total_votes || 1)) * 100) :
                                  Math.round((selectedScan.model_votes.legitimate_votes / (selectedScan.model_votes.total_votes || 1)) * 100)
                                }%
                              </text>
                            </svg>
                          </div>
                          <div style={{display: 'flex', justifyContent: 'center', gap: '32px'}}>
                            <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                              <div style={{width: '16px', height: '16px', borderRadius: '4px', background: '#51cf66'}} />
                              <span style={{fontSize: '14px', color: '#555', fontWeight: '600'}}>
                                Safe: {Math.round((selectedScan.model_votes.legitimate_votes / (selectedScan.model_votes.total_votes || 1)) * 100)}%
                              </span>
                            </div>
                            <div style={{display: 'flex', alignItems: 'center', gap: '8px'}}>
                              <div style={{width: '16px', height: '16px', borderRadius: '4px', background: '#ff6b6b'}} />
                              <span style={{fontSize: '14px', color: '#555', fontWeight: '600'}}>
                                Phishing: {Math.round((selectedScan.model_votes.phishing_votes / (selectedScan.model_votes.total_votes || 1)) * 100)}%
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Summary Cards */}
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                        gap: '16px'
                      }}>
                        <div style={{
                          background: 'white',
                          borderRadius: '12px',
                          padding: '20px',
                          textAlign: 'center',
                          border: '2px solid #00d4ff'
                        }}>
                          <div style={{fontSize: '36px', fontWeight: '700', color: '#00d4ff', marginBottom: '8px'}}>
                            {selectedScan.model_votes.total_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Total Votes</div>
                        </div>
                        <div style={{
                          background: 'white',
                          borderRadius: '12px',
                          padding: '20px',
                          textAlign: 'center',
                          border: '2px solid #ff4444'
                        }}>
                          <div style={{fontSize: '36px', fontWeight: '700', color: '#ff4444', marginBottom: '8px'}}>
                            {selectedScan.model_votes.phishing_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Phishing Votes</div>
                        </div>
                        <div style={{
                          background: 'white',
                          borderRadius: '12px',
                          padding: '20px',
                          textAlign: 'center',
                          border: '2px solid #00aa44'
                        }}>
                          <div style={{fontSize: '36px', fontWeight: '700', color: '#00aa44', marginBottom: '8px'}}>
                            {selectedScan.model_votes.legitimate_votes || 0}
                          </div>
                          <div style={{fontSize: '14px', color: '#666', fontWeight: '600'}}>Safe Votes</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* HTML Analysis Section */}
                  {selectedScan.html_analysis && (
                    <div style={{
                      background: '#f8f9fa',
                      borderRadius: '16px',
                      padding: '24px',
                      marginBottom: '24px'
                    }}>
                      <div style={{display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px'}}>
                        <Search size={24} color="#667eea" />
                        <h3 style={{margin: 0, fontSize: '18px', fontWeight: '700', color: '#1a1d2e'}}>
                          HTML Content Analysis
                        </h3>
                      </div>
                      <div style={{
                        background: 'white',
                        borderRadius: '12px',
                        padding: '20px',
                        marginBottom: '16px'
                      }}>
                        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px'}}>
                          <span style={{fontSize: '16px', fontWeight: '600', color: '#1a1d2e'}}>Suspicion Score</span>
                          <span style={{
                            fontSize: '24px',
                            fontWeight: '700',
                            color: selectedScan.html_analysis.suspicious ? '#ff4444' : '#00aa44'
                          }}>
                            {selectedScan.html_analysis.score || 0}/100
                          </span>
                        </div>
                        {selectedScan.html_analysis.evidence && selectedScan.html_analysis.evidence.length > 0 && (
                          <div>
                            <h4 style={{margin: '0 0 12px', fontSize: '14px', fontWeight: '600', color: '#495057'}}>
                              Evidence Found:
                            </h4>
                            <ul style={{margin: 0, paddingLeft: '20px'}}>
                              {selectedScan.html_analysis.evidence.map((evidence, idx) => (
                                <li key={idx} style={{fontSize: '14px', color: '#666', marginBottom: '8px', lineHeight: '1.6'}}>
                                  {evidence}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Timestamp */}
                  <div style={{
                    background: '#f8f9fa',
                    borderRadius: '16px',
                    padding: '20px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px'
                  }}>
                    <Clock size={20} color="#667eea" />
                    <div>
                      <div style={{fontSize: '13px', color: '#666', marginBottom: '4px'}}>Scan Timestamp</div>
                      <div style={{fontSize: '15px', fontWeight: '600', color: '#1a1d2e'}}>
                        {selectedScan.timestamp ? new Date(selectedScan.timestamp).toLocaleString() : 'N/A'}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default App;