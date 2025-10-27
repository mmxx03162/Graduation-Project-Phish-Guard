// src/components/ScanSummaryChart.jsx
// React component for displaying scan statistics in a visual chart format
// This component provides both numerical statistics and a pie chart visualization

import { useState, useEffect } from 'react';

function ScanSummaryChart({ scans = [] }) {
  // State for storing calculated statistics
  const [stats, setStats] = useState({
    total: 0,
    phishing: 0,
    legitimate: 0,
    phishingPercentage: 0,
    legitimatePercentage: 0
  });

  // Effect hook to calculate statistics when scans data changes
  useEffect(() => {
    if (scans && scans.length > 0) {
      // Count different types of scan results
      const phishingCount = scans.filter(scan => scan.result === 'Phishing').length;
      const legitimateCount = scans.filter(scan => scan.result === 'Legitimate').length;
      const total = scans.length;
      
      // Update statistics state
      setStats({
        total,
        phishing: phishingCount,
        legitimate: legitimateCount,
        phishingPercentage: total > 0 ? Math.round((phishingCount / total) * 100) : 0,
        legitimatePercentage: total > 0 ? Math.round((legitimateCount / total) * 100) : 0
      });
    }
  }, [scans]);

  // Create SVG pie chart for visual representation
  const createPieChart = () => {
    const radius = 80;  // Chart radius
    const centerX = 100;  // Center X coordinate
    const centerY = 100;  // Center Y coordinate
    
    // Handle empty data case
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

    // Calculate chart segments
    const circumference = 2 * Math.PI * radius;
    const phishingLength = (stats.phishing / stats.total) * circumference;
    const legitimateLength = (stats.legitimate / stats.total) * circumference;

    return (
      <g>
        {/* Background circle */}
        <circle
          cx={centerX}
          cy={centerY}
          r={radius}
          fill="none"
          stroke="#e2e8f0"
          strokeWidth="20"
        />
        {/* Phishing segment */}
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
        {/* Legitimate segment */}
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
      {/* Chart Header with Statistics */}
      <div className="chart-header">
        <h2>📊 Scan Statistics</h2>
        <div className="stats-grid">
          {/* Total Scans Card */}
          <div className="stat-card total">
            <div className="stat-number">{stats.total}</div>
            <div className="stat-label">Total Scans</div>
          </div>
          {/* Phishing Sites Card */}
          <div className="stat-card phishing">
            <div className="stat-number">{stats.phishing}</div>
            <div className="stat-label">Phishing Sites</div>
            <div className="stat-percentage">{stats.phishingPercentage}%</div>
          </div>
          {/* Legitimate Sites Card */}
          <div className="stat-card safe">
            <div className="stat-number">{stats.legitimate}</div>
            <div className="stat-label">Legitimate Sites</div>
            <div className="stat-percentage">{stats.legitimatePercentage}%</div>
          </div>
        </div>
      </div>
      
      {/* Chart Visualization */}
      <div className="chart-wrapper">
        <svg width="200" height="200" viewBox="0 0 200 200">
          {createPieChart()}
        </svg>
        {/* Chart Legend */}
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