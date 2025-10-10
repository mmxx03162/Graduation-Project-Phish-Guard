// src/components/ScanLogTable.jsx

import { useState } from 'react';

function ScanLogTable({ scans = [] }) {
  const [sortField, setSortField] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');
  const [filterResult, setFilterResult] = useState('all');

  const sortedScans = [...scans].sort((a, b) => {
    let aValue = a[sortField];
    let bValue = b[sortField];
    
    if (sortField === 'timestamp') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    }
    
    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });

  const filteredScans = sortedScans.filter(scan => {
    if (filterResult === 'all') return true;
    return scan.result === filterResult;
  });

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="table-container">
      <div className="table-controls">
        <div className="filter-controls">
          <label>Filter Results:</label>
          <select 
            value={filterResult} 
            onChange={(e) => setFilterResult(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Results</option>
            <option value="Phishing">Phishing Sites</option>
            <option value="Legitimate">Legitimate Sites</option>
          </select>
        </div>
        <div className="table-info">
          Showing {filteredScans.length} of {scans.length} records
        </div>
      </div>

      <div className="table-wrapper">
        <table className="scan-table">
          <thead>
            <tr>
              <th 
                className="sortable" 
                onClick={() => handleSort('url')}
              >
                🔗 URL
                {sortField === 'url' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th 
                className="sortable" 
                onClick={() => handleSort('result')}
              >
                🎯 Result
                {sortField === 'result' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th 
                className="sortable" 
                onClick={() => handleSort('timestamp')}
              >
                ⏰ Time
                {sortField === 'timestamp' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th>🔍 Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan="4" className="no-data">
                  No data to display
                </td>
              </tr>
            ) : (
              filteredScans.map(scan => (
                <tr key={scan.id} className="scan-row">
                  <td className="url-cell">
                    <a 
                      href={scan.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="url-link"
                    >
                      {scan.url}
                    </a>
                  </td>
                  <td>
                    <span 
                      className={`result-badge ${scan.result.toLowerCase()}`}
                    >
                      {scan.result === 'Phishing' ? '⚠️ Phishing' : '✅ Legitimate'}
                    </span>
                  </td>
                  <td className="timestamp-cell">
                    {new Date(scan.timestamp).toLocaleString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </td>
                  <td>
                    <button 
                      className="action-btn"
                      onClick={() => window.open(scan.url, '_blank')}
                      title="Open URL"
                    >
                      🔗
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default ScanLogTable;