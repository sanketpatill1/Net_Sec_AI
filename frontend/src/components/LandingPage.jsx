import React from 'react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  EyeOff,
  Layers,
  Lock,
  Server,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';

const LandingPage = ({ onNavigate }) => {
  return (
    <div className="landing-page">
      {/* Hero Section */}
      <section className="hero-section text-center">
        <div className="badge-pill mb-4">
          <Zap size={14} /> Production AI Security Classifier Active
        </div>

        <h1 className="hero-main-title">
          Intelligent URL <br />
          <span className="title-gradient">Security & Threat Defense</span>
        </h1>

        <p className="hero-subtitle">
          Proactively identify malicious, phishing, defacement, and malware websites before you click.
          Safe, string-only lexical feature analysis with zero outbound network footprint.
        </p>

        <div className="flex justify-center gap-4 hero-cta-row">
          <button className="btn-primary" onClick={() => onNavigate('predict')} style={{ padding: '1rem 2.25rem', fontSize: '1.1rem' }}>
            <ShieldCheck size={22} />
            Analyze Website URL
          </button>
          <button className="btn-outline" onClick={() => onNavigate('about')} style={{ padding: '1rem 2.25rem', fontSize: '1.1rem' }}>
            <Database size={22} />
            Model Architecture & Metrics
          </button>
        </div>
      </section>

      {/* Stats Counter Bar */}
      <section className="stats-counter-bar mb-12">
        <div className="stat-counter-item">
          <span className="stat-counter-num text-cyan">40,438</span>
          <span className="stat-counter-label">Cleaned Dataset Samples</span>
        </div>
        <div className="stat-counter-item">
          <span className="stat-counter-num text-green">92.98%</span>
          <span className="stat-counter-label">Model Test Accuracy</span>
        </div>
        <div className="stat-counter-item">
          <span className="stat-counter-num text-indigo">24</span>
          <span className="stat-counter-label">Extracted URL Features</span>
        </div>
        <div className="stat-counter-item">
          <span className="stat-counter-num text-amber">0 ms</span>
          <span className="stat-counter-label">Outbound External Traffic</span>
        </div>
      </section>

      {/* Features Grid */}
      <section className="mb-12">
        <div className="text-center mb-8">
          <h2 style={{ fontSize: '2.25rem', marginBottom: '0.75rem' }}>Enterprise-Grade Protection</h2>
          <p className="text-muted">Multi-layered security analysis combining machine learning with heuristic intelligence.</p>
        </div>

        <div className="grid grid-cols-3 gap-6">
          <div className="glass-card feature-hover-card">
            <div className="step-icon mb-4"><Cpu size={26} /></div>
            <h3 className="mb-2" style={{ fontSize: '1.25rem' }}>Random Forest ML Core</h3>
            <p className="text-muted" style={{ fontSize: '0.92rem', lineHeight: 1.6 }}>
              Trained on 40,438 real-world URLs to classify threats into Benign, Defacement, Phishing, and Malware with true probability distributions.
            </p>
          </div>

          <div className="glass-card feature-hover-card">
            <div className="step-icon mb-4"><Lock size={26} /></div>
            <h3 className="mb-2" style={{ fontSize: '1.25rem' }}>24 Structural Features</h3>
            <p className="text-muted" style={{ fontSize: '0.92rem', lineHeight: 1.6 }}>
              Evaluates Shannon URL entropy, token ratios, IPv4/IPv6 hosts, subdomain depths, delimiter patterns, and high-risk TLD indicators.
            </p>
          </div>

          <div className="glass-card feature-hover-card">
            <div className="step-icon mb-4"><EyeOff size={26} /></div>
            <h3 className="mb-2" style={{ fontSize: '1.25rem' }}>Zero Outbound Visits (SSRF Safe)</h3>
            <p className="text-muted" style={{ fontSize: '0.92rem', lineHeight: 1.6 }}>
              Pure in-memory string analysis means the server never connects to untrusted remote hosts, eliminating SSRF and malware download vectors.
            </p>
          </div>
        </div>
      </section>

      {/* Quick Launch Banner */}
      <section className="glass-card cta-banner text-center mb-8">
        <h2 style={{ fontSize: '1.85rem', marginBottom: '0.75rem' }}>Ready to analyze a suspicious link?</h2>
        <p className="text-muted mb-6" style={{ maxWidth: '520px', margin: '0 auto 1.5rem' }}>
          Paste any website URL into our real-time security dashboard for instant classification and risk explanation.
        </p>
        <button className="btn-primary" onClick={() => onNavigate('predict')} style={{ padding: '0.85rem 2rem', fontSize: '1.05rem' }}>
          Open Security Dashboard <ArrowRight size={18} />
        </button>
      </section>
    </div>
  );
};

export default LandingPage;
