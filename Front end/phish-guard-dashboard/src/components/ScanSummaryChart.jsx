// src/components/ScanSummaryChart.jsx

import { useState, useEffect } from 'react';

function ScanSummaryChart({ scans = [] }) {
  const [stats, setStats] = useState({
    total: 0,
    phishing: 0,
    legitimate: 0,
    phishingPercentage: 0,
    legitimatePercentage: 0
  });

  useEffect(() => {
    if (scans && scans.length > 0) {
      const phishingCount = scans.filter(scan => scan.result === 'Phishing').length;
      const legitimateCount = scans.filter(scan => scan.result === 'Legitimate').length;
      const total = scans.length;
      
      setStats({
        total,
        phishing: phishingCount,
        legitimate: legitimateCount,
        phishingPercentage: total > 0 ? Math.round((phishingCount / total) * 100) : 0,
        legitimatePercentage: total > 0 ? Math.round((legitimateCount / total) * 100) : 0
      });
    }
  }, [scans]);

  const createPieChart = () => {
    const radius = 80;
    const centerX = 100;
    const centerY = 100;
    
    if (stats.total === 0) {
      return (
        <circle
          cx={centerX}
          cy={centerY}
          r={radius}
          fill="#e2e8f0"
          stroke="#cbd5e0"
          strokeWidth="2"
        />
      );
    }

    const circumference = 2 * Math.PI * radius;
    const phishingLength = (stats.phishing / stats.total) * circumference;
    const legitimateLength = (stats.legitimate / stats.total) * circumference;

    return (
      <g>
        <circle
          cx={centerX}
          cy={centerY}
          r={radius}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth="20"
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={radius}
          fill="none"
          stroke="#ef4444"
          strokeWidth="20"
          strokeDasharray={`${phishingLength} ${circumference}`}
          strokeDashoffset="0"
          transform={`rotate(-90 ${centerX} ${centerY})`}
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={radius}
          fill="none"
          stroke="#10b981"
          strokeWidth="20"
          strokeDasharray={`${legitimateLength} ${circumference}`}
          strokeDashoffset={`-${phishingLength}`}
          transform={`rotate(-90 ${centerX} ${centerY})`}
        />
      </g>
    );
  };

  return (
    <div className="chart-container">
      <div className="chart-header">
        <h2>📊 Scan Statistics</h2>
        <div className="stats-grid">
          <div className="stat-card total">
            <div className="stat-number">{stats.total}</div>
            <div className="stat-label">Total Scans</div>
          </div>
          <div className="stat-card phishing">
            <div className="stat-number">{stats.phishing}</div>
            <div className="stat-label">Phishing Sites</div>
            <div className="stat-percentage">{stats.phishingPercentage}%</div>
          </div>
          <div className="stat-card safe">
            <div className="stat-number">{stats.legitimate}</div>
            <div className="stat-label">Legitimate Sites</div>
            <div className="stat-percentage">{stats.legitimatePercentage}%</div>
          </div>
        </div>
      </div>
      
      <div className="chart-wrapper">
        <svg width="200" height="200" viewBox="0 0 200 200">
          {createPieChart()}
        </svg>
        <div className="chart-legend">
          <div className="legend-item">
            <div className="legend-color phishing"></div>
            <span>Phishing Sites ({stats.phishingPercentage}%)</span>
          </div>
          <div className="legend-item">
            <div className="legend-color safe"></div>
            <span>Legitimate Sites ({stats.legitimatePercentage}%)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ScanSummaryChart;