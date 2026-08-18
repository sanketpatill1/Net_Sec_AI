import React, { useEffect, useState } from 'react';
import {
  Activity,
  Award,
  BarChart3,
  CheckCircle,
  Cpu,
  Database,
  FileCode,
  Layers,
  Lock,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';

const MODEL_INFO_API = 'http://127.0.0.1:8000/api/model-info';

const AboutProject = () => {
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(MODEL_INFO_API)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setModelInfo(data))
      .catch(() => setModelInfo(null))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="about-container">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="badge-pill mb-3">
          <Award size={14} /> Machine Learning Architecture & Audits
        </div>
        <h1 className="hero-title" style={{ fontSize: '2.75rem', marginBottom: '0.75rem' }}>
          How <span className="title-gradient">NetSecAI</span> Operates
        </h1>
        <p className="text-muted" style={{ maxWidth: '640px', margin: '0 auto' }}>
          An end-to-end overview of data sanitization, deterministic lexical extraction, machine learning classification, and explainable heuristic risk scoring.
        </p>
      </div>

      <div style={{ maxWidth: '960px', margin: '0 auto' }}>
        {/* ML Metrics Card */}
        <div className="glass-card mb-8">
          <div className="flex items-center gap-3 mb-4">
            <BarChart3 className="text-cyan" size={24} />
            <h2 style={{ fontSize: '1.4rem' }}>Production Model Performance</h2>
          </div>

          <div className="stats-row mb-6">
            <div className="stat-card">
              <span className="stat-label">Model Architecture</span>
              <strong className="stat-value text-cyan">
                {modelInfo?.model_type || 'RandomForestClassifier'}
              </strong>
              <span className="stat-sub">300 Trees (Balanced Subsample)</span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Overall Accuracy</span>
              <strong className="stat-value text-green">
                {modelInfo?.test_evaluation?.accuracy
                  ? `${(modelInfo.test_evaluation.accuracy * 100).toFixed(2)}%`
                  : '92.98%'}
              </strong>
              <span className="stat-sub">Evaluated on 6,066 test URLs</span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Macro F1 Score</span>
              <strong className="stat-value text-indigo">
                {modelInfo?.test_evaluation?.macro_f1
                  ? `${(modelInfo.test_evaluation.macro_f1 * 100).toFixed(2)}%`
                  : '85.41%'}
              </strong>
              <span className="stat-sub">Multi-Class Balanced F1</span>
            </div>
            <div className="stat-card">
              <span className="stat-label">ROC-AUC (Macro OvR)</span>
              <strong className="stat-value text-amber">
                {modelInfo?.test_evaluation?.roc_auc_macro_ovr
                  ? `${(modelInfo.test_evaluation.roc_auc_macro_ovr * 100).toFixed(2)}%`
                  : '97.49%'}
              </strong>
              <span className="stat-sub">One-vs-Rest Discriminative Power</span>
            </div>
          </div>

          {/* Per Class Metrics Table */}
          <div className="table-responsive">
            <table className="custom-metrics-table">
              <thead>
                <tr>
                  <th>Class Label</th>
                  <th>Target Security Status</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1-Score</th>
                  <th>Test Samples</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><span className="chip chip-safe">Benign</span></td>
                  <td><strong>SAFE</strong></td>
                  <td>93.91%</td>
                  <td>97.50%</td>
                  <td>95.67%</td>
                  <td>4,478</td>
                </tr>
                <tr>
                  <td><span className="chip chip-malicious">Defacement</span></td>
                  <td><strong>MALICIOUS</strong></td>
                  <td>87.43%</td>
                  <td>80.86%</td>
                  <td>84.01%</td>
                  <td>1,118</td>
                </tr>
                <tr>
                  <td><span className="chip chip-malicious">Phishing</span></td>
                  <td><strong>MALICIOUS</strong></td>
                  <td>96.17%</td>
                  <td>81.57%</td>
                  <td>88.27%</td>
                  <td>369</td>
                </tr>
                <tr>
                  <td><span className="chip chip-malicious">Malware</span></td>
                  <td><strong>MALICIOUS</strong></td>
                  <td>90.00%</td>
                  <td>62.38%</td>
                  <td>73.68%</td>
                  <td>101</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* 4-Stage Security Pipeline */}
        <div className="glass-card mb-8">
          <div className="flex items-center gap-3 mb-6">
            <Network className="text-cyan" size={24} />
            <h2 style={{ fontSize: '1.4rem' }}>End-to-End Analysis Workflow</h2>
          </div>

          <div className="pipeline-steps-grid">
            <div className="pipeline-card">
              <div className="step-number">1</div>
              <div className="step-icon"><Database size={22} /></div>
              <h3>URL Normalization & Validation</h3>
              <p className="text-muted">
                Incoming URLs are checked for strict RFC 3986 compliance, maximum 2,048 characters, control characters, IDNA encoding, and restricted to HTTP/HTTPS schemes. Dangerous protocols like <code>javascript:</code> and <code>file:</code> are strictly rejected.
              </p>
            </div>

            <div className="pipeline-card">
              <div className="step-number">2</div>
              <div className="step-icon"><Layers size={22} /></div>
              <h3>24-Feature Lexical Extraction</h3>
              <p className="text-muted">
                Extracts deterministic features including Shannon URL entropy, token length ratios, subdomain counts, keyword occurrences, digit densities, and suspicious TLD flags. Zero external HTTP requests are made.
              </p>
            </div>

            <div className="pipeline-card">
              <div className="step-number">3</div>
              <div className="step-icon"><Cpu size={22} /></div>
              <h3>Machine Learning Inference</h3>
              <p className="text-muted">
                A pre-trained Random Forest classifier (300 estimators, balanced sub-sampling) evaluates the feature vector and generates true multi-class probabilities across <code>benign</code>, <code>defacement</code>, <code>phishing</code>, and <code>malware</code>.
              </p>
            </div>

            <div className="pipeline-card">
              <div className="step-number">4</div>
              <div className="step-icon"><ShieldAlert size={22} /></div>
              <h3>Explainable Heuristic Risk Scoring</h3>
              <p className="text-muted">
                A parallel rule-based risk engine scores structural indicators (e.g., IP address hosts, excessive subdomains, @ symbols, abused TLDs) on a 0–100 scale, providing human-readable explanations alongside ML predictions.
              </p>
            </div>
          </div>
        </div>

        {/* Project Details Grid */}
        <div className="grid grid-cols-2 gap-4">
          <div className="glass-card">
            <h3 className="mb-3" style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Lock className="text-cyan" size={20} /> Security & SSRF Protection
            </h3>
            <p className="text-muted" style={{ lineHeight: 1.6, fontSize: '0.9rem' }}>
              Unlike traditional website scanners that fetch the HTML DOM, this analyzer inspects only the URL text representation. This eliminates server-side request forgery (SSRF), malware infection via arbitrary downloads, and cross-site scripting vulnerabilities.
            </p>
          </div>

          <div className="glass-card">
            <h3 className="mb-3" style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server className="text-indigo" size={20} /> Technical Stack
            </h3>
            <ul className="tech-stack-list text-muted" style={{ fontSize: '0.9rem' }}>
              <li><strong>Frontend:</strong> React 19, Vite, Lucide Icons, Vanilla CSS Design System</li>
              <li><strong>Backend:</strong> FastAPI, Uvicorn, Pydantic, scikit-learn, joblib</li>
              <li><strong>Dataset:</strong> 40,438 cleaned raw URLs (Benign, Defacement, Phishing, Malware)</li>
              <li><strong>Zero Outbound Traffic:</strong> Safe string-only real-time evaluation</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AboutProject;
