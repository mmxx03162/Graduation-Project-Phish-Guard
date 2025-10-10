// src/App.jsx - متوافق مع Django API

import { useState, useEffect } from 'react';
import './App.css';
import ScanLogTable from './components/ScanLogTable';
import ScanSummaryChart from './components/ScanSummaryChart';

function App() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);

  // Fetch data from Django Backend
  const fetchScans = async () => {
    try {
      setLoading(true);
      
      console.log('🔄 Attempting to connect to backend...');
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 seconds
      
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
      
      // Django API returns paginated data with 'results' key
      const results = data.results || data;
      
      console.log('✅ Backend connected! Records:', results.length);
      
      setScans(results);
      setLastUpdate(new Date());
      setError(null);
      setBackendConnected(true);
      
    } catch (err) {
      console.error('❌ Backend error:', err);
      
      let errorMessage = 'Cannot connect to backend';
      
      if (err.name === 'AbortError') {
        errorMessage = 'Connection timeout (5s) - Is Django running?';
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

  useEffect(() => {
    fetchScans();
    
    // Auto refresh every 30 seconds
    const interval = setInterval(() => {
      if (!loading && backendConnected) {
        fetchScans();
      }
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  // Calculate statistics
  const stats = {
    total: scans.length,
    phishing: scans.filter(s => s.result === 'Phishing').length,
    legitimate: scans.filter(s => s.result === 'Legitimate').length,
  };

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <h1>🛡️ Phish-Guard Dashboard</h1>
        <div className="header-info">
          {lastUpdate && (
            <span className="last-update">
              Last updated: {lastUpdate.toLocaleTimeString()}
            </span>
          )}
          <button 
            className="refresh-btn" 
            onClick={fetchScans}
            disabled={loading}
          >
            {loading ? '⏳' : '🔄'} Refresh
          </button>
        </div>
      </header>

      {/* Connection Status Banner */}
      <div style={{
        background: backendConnected ? '#c6f6d5' : '#fed7d7',
        border: `2px solid ${backendConnected ? '#38a169' : '#e53e3e'}`,
        borderRadius: '12px',
        padding: '16px 24px',
        marginBottom: '24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{display: 'flex', alignItems: 'center', gap: '12px'}}>
          <div style={{fontSize: '24px'}}>
            {backendConnected ? '✅' : '❌'}
          </div>
          <div>
            <strong style={{color: '#1a202c', display: 'block'}}>
              {backendConnected ? '🟢 Backend Connected' : '🔴 Backend Disconnected'}
            </strong>
            <span style={{fontSize: '14px', color: '#4a5568'}}>
              {backendConnected 
                ? `Connected to Django API - ${stats.total} records loaded`
                : error || 'Unable to reach Django backend'}
            </span>
          </div>
        </div>
        {!backendConnected && (
          <button 
            onClick={fetchScans}
            disabled={loading}
            style={{
              background: '#e53e3e',
              color: 'white',
              border: 'none',
              padding: '10px 20px',
              borderRadius: '8px',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontWeight: '600',
              fontSize: '14px',
              opacity: loading ? 0.6 : 1
            }}
          >
            {loading ? '⏳ Connecting...' : '🔌 Retry Connection'}
          </button>
        )}
      </div>

      {/* Loading Indicator */}
      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          <span>Loading data from backend...</span>
        </div>
      )}

      {/* Error Details */}
      {error && !backendConnected && (
        <div className="error-message">
          <div className="error-content">
            <div className="error-icon">⚠️</div>
            <div className="error-text">
              <h3>Backend Connection Failed</h3>
              <p>{error}</p>
              <div className="error-help">
                <p><strong>Quick Fix Steps:</strong></p>
                <ol>
                  <li>Open terminal in backend folder</li>
                  <li>Run: <code>python manage.py runserver</code></li>
                  <li>Verify: <code>http://127.0.0.1:8000/api/logs/</code></li>
                  <li>Click "Retry Connection" above</li>
                </ol>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Show content only if connected or has data */}
      {(backendConnected || scans.length > 0) && (
        <>
          {/* Statistics Cards */}
          <section className="additional-stats">
            <div className="stats-cards">
              <div className="stat-card">
                <h3>📊 Total Scans</h3>
                <div className="stat-value">{stats.total}</div>
              </div>
              <div className="stat-card" style={{background: '#e53e3e'}}>
                <h3>⚠️ Phishing Sites</h3>
                <div className="stat-value">{stats.phishing}</div>
                <small style={{opacity: 0.9}}>
                  {stats.total > 0 ? Math.round((stats.phishing / stats.total) * 100) : 0}%
                </small>
              </div>
              <div className="stat-card" style={{background: '#38a169'}}>
                <h3>✅ Legitimate Sites</h3>
                <div className="stat-value">{stats.legitimate}</div>
                <small style={{opacity: 0.9}}>
                  {stats.total > 0 ? Math.round((stats.legitimate / stats.total) * 100) : 0}%
                </small>
              </div>
            </div>
          </section>

          {/* Chart Section */}
          <section className="chart-section">
            <h2>📊 Scan Statistics</h2>
            <ScanSummaryChart scans={scans} />
          </section>

          {/* Table Section */}
          <section className="table-section">
            <h2>📋 Detailed Scan Log</h2>
            <ScanLogTable scans={scans} />
          </section>
        </>
      )}

      {/* Empty State */}
      {!loading && !backendConnected && scans.length === 0 && (
        <div style={{
          textAlign: 'center',
          padding: '60px 20px',
          background: '#f7fafc',
          borderRadius: '12px',
          border: '2px dashed #cbd5e0'
        }}>
          <div style={{fontSize: '64px', marginBottom: '20px'}}>🔌</div>
          <h2 style={{color: '#2d3748', marginBottom: '10px'}}>Backend Not Connected</h2>
          <p style={{color: '#718096', marginBottom: '20px'}}>
            Please start the Django backend to view scan data.
          </p>
          <button 
            onClick={fetchScans}
            disabled={loading}
            style={{
              background: '#3182ce',
              color: 'white',
              border: 'none',
              padding: '12px 24px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontWeight: '600',
              fontSize: '16px'
            }}
          >
            Try Connect Now
          </button>
        </div>
      )}
    </div>
  );
}

export default App;