// src/components/ScanLogTable.jsx
// React component for displaying scan results in a sortable and filterable table
// This component provides comprehensive data visualization for URL scan results

import { useState } from 'react';

function ScanLogTable({ scans = [] }) {
  // State management for table functionality
  const [sortField, setSortField] = useState('timestamp');  // Current sort field
  const [sortOrder, setSortOrder] = useState('desc');  // Sort order (asc/desc)
  const [filterResult, setFilterResult] = useState('all');  // Result filter

  // Sort scans based on current sort settings
  const sortedScans = [...scans].sort((a, b) => {
    let aValue = a[sortField];
    let bValue = b[sortField];
    
    // Handle timestamp sorting with proper date conversion
    if (sortField === 'timestamp') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    }
    
    // Apply sort order
    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });

  // Filter scans based on result type
  const filteredScans = sortedScans.filter(scan => {
    if (filterResult === 'all') return true;
    return scan.result === filterResult;
  });

  // Handle column sorting
  const handleSort = (field) => {
    if (sortField === field) {
      // Toggle sort order if clicking the same field
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new sort field with default descending order
      setSortField(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="table-container">
      {/* Table Controls Section */}
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

      {/* Table Wrapper */}
      <div className="table-wrapper">
        <table className="scan-table">
          <thead>
            <tr>
              {/* URL Column - Sortable */}
              <th 
                className="sortable" 
                onClick={() => handleSort('url')}
              >
                🔗 URL
                {sortField === 'url' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              {/* Result Column - Sortable */}
              <th 
                className="sortable" 
                onClick={() => handleSort('result')}
              >
                🎯 Result
                {sortField === 'result' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              {/* Timestamp Column - Sortable */}
              <th 
                className="sortable" 
                onClick={() => handleSort('timestamp')}
              >
                ⏰ Time
                {sortField === 'timestamp' && (sortOrder === 'asc' ? ' ↑' : ' ↓')}
              </th>
              {/* Actions Column - Non-sortable */}
              <th>🔍 Actions</th>
            </tr>
          </thead>
          <tbody>
            {/* Handle empty data state */}
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan="4" className="no-data">
                  No data to display
                </td>
              </tr>
            ) : (
              /* Render scan results */
              filteredScans.map(scan => (
                <tr key={scan.id} className="scan-row">
                  {/* URL Cell with clickable link */}
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
                  {/* Result Cell with status badge */}
                  <td>
                    <span 
                      className={`result-badge ${scan.result.toLowerCase()}`}
                    >
                      {scan.result === 'Phishing' ? '⚠️ Phishing' : '✅ Legitimate'}
                    </span>
                  </td>
                  {/* Timestamp Cell with formatted date */}
                  <td className="timestamp-cell">
                    {new Date(scan.timestamp).toLocaleString('en-US', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit'
                    })}
                  </td>
                  {/* Actions Cell with open URL button */}
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