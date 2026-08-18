import React, { useState } from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  ExternalLink,
  Info,
  Layers,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';

const API_URL = 'http://127.0.0.1:8000/api/analyze-url';

const SAMPLE_URLS = [
  { label: 'Google (Legitimate)', url: 'https://google.com', type: 'safe' },
  { label: 'GitHub (Portal)', url: 'https://github.com', type: 'safe' },
  { label: 'IP Login (Suspicious)', url: 'http://192.168.1.1/login/verify-bank-account', type: 'suspicious' },
  { label: 'Apple Phishing (Attack)', url: 'http://1-configurazione-supporto-apple.store-contatta.bimabn.com/c/Apple-id/', type: 'malicious' },
  { label: 'Joomla Exploit (Defacement)', url: 'http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=1', type: 'malicious' },
];

const Dashboard = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [showFeatures, setShowFeatures] = useState(false);

  const validateUrl = (value) => {
    try {
      const parsed = new URL(value);
      return ['http:', 'https:'].includes(parsed.protocol) && Boolean(parsed.hostname);
    } catch {
      return false;
    }
  };

  const handleAnalyze = async (targetUrl) => {
    const candidate = (targetUrl || url).trim();
    setError('');
    setResult(null);

    if (!candidate) {
      setError('Please enter a website URL to analyze.');
      return;
    }

    if (!validateUrl(candidate)) {
      setError('Enter a valid URL starting with http:// or https:// (e.g., https://example.com).');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: candidate }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || `Server returned status ${response.status}`);
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Analysis failed. Please ensure the backend is running at http://127.0.0.1:8000.');
    } finally {
      setLoading(false);
    }
  };

  const getStatusConfig = (status) => {
    switch (status) {
      case 'SAFE':
        return {
          icon: ShieldCheck,
          className: 'status-safe',
          badgeText: 'SAFE TO VISIT',
          color: 'var(--accent-green)',
          bg: 'rgba(16, 185, 129, 0.15)',
          border: 'rgba(16, 185, 129, 0.4)',
        };
      case 'SUSPICIOUS':
        return {
          icon: AlertTriangle,
          className: 'status-suspicious',
          badgeText: 'POTENTIALLY SUSPICIOUS',
          color: 'var(--accent-amber)',
          bg: 'rgba(245, 158, 11, 0.15)',
          border: 'rgba(245, 158, 11, 0.4)',
        };
      case 'MALICIOUS':
      default:
        return {
          icon: ShieldAlert,
          className: 'status-malicious',
          badgeText: 'MALICIOUS THREAT DETECTED',
          color: 'var(--accent-red)',
          bg: 'rgba(239, 68, 68, 0.15)',
          border: 'rgba(239, 68, 68, 0.4)',
        };
    }
  };

  const statusConfig = result ? getStatusConfig(result.security_status) : null;
  const StatusIcon = statusConfig ? statusConfig.icon : null;

  return (
    <div className="dashboard-container">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="badge-pill mb-3">
          <Zap size={14} /> Real-Time URL Security Intelligence
        </div>
        <h1 className="hero-title" style={{ fontSize: '2.75rem', marginBottom: '0.75rem' }}>
          Website Security <span className="title-gradient">Analyzer</span>
        </h1>
        <p className="text-muted" style={{ maxWidth: '640px', margin: '0 auto' }}>
          Evaluate any web URL using structural heuristics and our 24-feature machine learning model.
          Analysis is performed entirely locally on the URL string without visiting untrusted servers.
        </p>
      </div>

      <div style={{ maxWidth: '880px', margin: '0 auto' }}>
        {/* Input Card */}
        <div className="glass-card mb-6" style={{ position: 'relative' }}>
          <form onSubmit={(e) => { e.preventDefault(); handleAnalyze(); }}>
            <label htmlFor="url-input" style={{ display: 'block', fontWeight: 600, marginBottom: '0.75rem', fontSize: '0.95rem' }}>
              Enter Website URL
            </label>
            <div className="url-input-group">
              <div className="url-icon-wrapper">
                <Search size={20} className="text-muted" />
              </div>
              <input
                id="url-input"
                type="url"
                className="url-field"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/login"
                maxLength="2048"
                autoComplete="url"
                disabled={loading}
              />
              <button className="btn-primary analyze-btn" type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <span className="spinner" /> Analyzing...
                  </>
                ) : (
                  <>
                    <Activity size={18} /> Analyze URL
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Quick Sample Chips */}
          <div className="sample-chips-row">
            <span className="text-muted" style={{ fontSize: '0.8rem', fontWeight: 500 }}>
              Try sample:
            </span>
            {SAMPLE_URLS.map((sample) => (
              <button
                key={sample.label}
                type="button"
                className={`chip chip-${sample.type}`}
                onClick={() => {
                  setUrl(sample.url);
                  handleAnalyze(sample.url);
                }}
                disabled={loading}
              >
                {sample.label}
              </button>
            ))}
          </div>

          {error && (
            <div className="alert-box alert-error mt-4">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Results Section */}
        {result && (
          <div className={`analysis-result-card ${statusConfig.className} mb-8 animate-fade-in`}>
            {/* Top Status Header */}
            <div className="result-header-row">
              <div className="status-badge-large" style={{ backgroundColor: statusConfig.bg, borderColor: statusConfig.border, color: statusConfig.color }}>
                <StatusIcon size={26} />
                <span>{statusConfig.badgeText}</span>
              </div>
              <div className="model-tag">
                <Cpu size={14} />
                <span>{result.model_name ? `Model: ${result.model_name}` : 'Heuristic Engine'}</span>
              </div>
            </div>

            {/* Target URL */}
            <div className="target-url-display">
              <span className="text-muted" style={{ fontSize: '0.8rem', display: 'block', marginBottom: '0.25rem' }}>
                Analyzed Target:
              </span>
              <a href={result.url} target="_blank" rel="noopener noreferrer" className="analyzed-url-link">
                {result.url} <ExternalLink size={14} style={{ display: 'inline', marginLeft: '4px' }} />
              </a>
            </div>

            {/* Core Metrics Grid */}
            <div className="metrics-dashboard-grid">
              <div className="metric-box">
                <span className="metric-label">Security Classification</span>
                <strong className="metric-value" style={{ color: statusConfig.color }}>
                  {result.threat_type || result.prediction.toUpperCase()}
                </strong>
                <span className="metric-sub">{result.security_status} status</span>
              </div>

              <div className="metric-box">
                <span className="metric-label">Model Confidence</span>
                <strong className="metric-value">
                  {result.confidence != null ? `${Math.round(result.confidence * 100)}%` : 'N/A'}
                </strong>
                <span className="metric-sub">
                  {result.model_used ? 'Random Forest Probability' : 'Heuristic estimate'}
                </span>
              </div>

              <div className="metric-box">
                <span className="metric-label">Heuristic Risk Score</span>
                <strong className="metric-value" style={{ color: result.risk_score > 50 ? 'var(--accent-red)' : result.risk_score > 25 ? 'var(--accent-amber)' : 'var(--accent-green)' }}>
                  {result.risk_score}<span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/100</span>
                </strong>
                <span className="metric-sub">{result.risk_level} Risk Tier</span>
              </div>
            </div>

            {/* Multiclass Probabilities Distribution */}
            {result.probabilities && (
              <div className="probability-section">
                <h3 className="section-subtitle">
                  <Layers size={16} /> Class Probability Distribution
                </h3>
                <div className="prob-bars-grid">
                  {Object.entries(result.probabilities).map(([cls, prob]) => {
                    const percent = Math.round(prob * 100);
                    const isWinner = result.prediction.toLowerCase() === cls.toLowerCase();
                    const barColor =
                      cls === 'benign'
                        ? 'var(--accent-green)'
                        : cls === 'phishing'
                        ? 'var(--accent-red)'
                        : cls === 'defacement'
                        ? 'var(--accent-amber)'
                        : 'var(--accent-purple)';

                    return (
                      <div key={cls} className={`prob-card ${isWinner ? 'prob-winner' : ''}`}>
                        <div className="prob-card-header">
                          <span className="prob-class-name">
                            {cls.charAt(0).toUpperCase() + cls.slice(1)}
                            {isWinner && <span className="winner-tag">Primary</span>}
                          </span>
                          <span className="prob-pct">{percent}%</span>
                        </div>
                        <div className="progress-track">
                          <div
                            className="progress-fill"
                            style={{
                              width: `${Math.max(4, percent)}%`,
                              backgroundColor: barColor,
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Detected Indicators */}
            <div className="indicators-section">
              <h3 className="section-subtitle">
                <Shield size={16} /> Detected Security Indicators
              </h3>
              <ul className="indicator-list">
                {result.indicators.map((indicator, idx) => (
                  <li key={idx} className="indicator-item">
                    <CheckCircle2 size={16} className="text-cyan" />
                    <span>{indicator}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Expandable 24-Feature Inspector */}
            {result.features && (
              <div className="feature-inspector-container">
                <button
                  type="button"
                  className="feature-toggle-btn"
                  onClick={() => setShowFeatures(!showFeatures)}
                >
                  <span>
                    <Info size={16} /> Extracted URL Features ({Object.keys(result.features).length} parameters)
                  </span>
                  {showFeatures ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                </button>

                {showFeatures && (
                  <div className="features-table-wrapper animate-fade-in">
                    <div className="features-grid">
                      {Object.entries(result.features).map(([key, val]) => (
                        <div key={key} className="feature-cell">
                          <span className="feature-name">{key.replace(/_/g, ' ')}</span>
                          <span className="feature-val">{typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(4) : String(val)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Notice Footer */}
            <div className="result-footer">
              <p className="notice-text">{result.notice}</p>
              <button
                className="btn-outline reset-btn"
                type="button"
                onClick={() => {
                  setUrl('');
                  setResult(null);
                  setError('');
                }}
              >
                <RefreshCw size={16} /> Analyze Another URL
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
