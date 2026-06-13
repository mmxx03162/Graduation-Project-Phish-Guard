import { Component } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, errorInfo) {
    // Keep console signal for dev troubleshooting.
    // eslint-disable-next-line no-console
    console.error('UI crashed:', error, errorInfo);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
          <div style={{
            width: 'min(720px, 100%)',
            background: '#0d1424',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 12,
            padding: 22,
            color: '#e2e8f0',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
              <AlertTriangle size={18} color="#ef4444" />
              <div style={{ fontWeight: 800, letterSpacing: 0.6 }}>Something went wrong</div>
            </div>
            <div style={{ opacity: 0.85, fontSize: 13, lineHeight: 1.6 }}>
              {String(this.state.error?.message || this.state.error)}
            </div>
            <button
              onClick={() => window.location.reload()}
              style={{
                marginTop: 14,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '10px 14px',
                borderRadius: 10,
                border: '1px solid rgba(0, 212, 255, 0.22)',
                background: 'rgba(0, 212, 255, 0.10)',
                color: '#00d4ff',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={14} />
              Reload
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

