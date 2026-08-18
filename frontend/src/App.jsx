import { useState } from 'react';
import LandingPage from './components/LandingPage';
import Dashboard from './components/Dashboard';
import AboutProject from './components/AboutProject';
import { Shield, ShieldAlert, Activity, Server, FileSearch } from 'lucide-react';
import './index.css';

function App() {
  const [currentPage, setCurrentPage] = useState('home');

  const renderPage = () => {
    switch(currentPage) {
      case 'home':
        return <LandingPage onNavigate={setCurrentPage} />;
      case 'predict':
        return <Dashboard />;
      case 'about':
        return <AboutProject />;
      default:
        return <LandingPage onNavigate={setCurrentPage} />;
    }
  };

  return (
    <div className="app-container">
      <nav className="navbar">
        <a href="#" className="nav-logo" onClick={(e) => { e.preventDefault(); setCurrentPage('home'); }}>
          <Shield className="text-cyan-400" size={32} style={{ color: 'var(--accent-cyan)' }} />
          <span>NetSec<span style={{ color: 'var(--accent-cyan)' }}>AI</span></span>
        </a>
        <div className="nav-links">
          <a href="#" className={`nav-link ${currentPage === 'home' ? 'active' : ''}`} onClick={(e) => { e.preventDefault(); setCurrentPage('home'); }}>Home</a>
          <a href="#" className={`nav-link ${currentPage === 'predict' ? 'active' : ''}`} onClick={(e) => { e.preventDefault(); setCurrentPage('predict'); }}>Analyze URL</a>
          <a href="#" className={`nav-link ${currentPage === 'about' ? 'active' : ''}`} onClick={(e) => { e.preventDefault(); setCurrentPage('about'); }}>About Model</a>
        </div>
        <button className="btn-primary" onClick={() => setCurrentPage('predict')}>
          Launch Dashboard
        </button>
      </nav>

      <main>
        {renderPage()}
      </main>
      
      <footer style={{ marginTop: '4rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem', padding: '2rem 0', borderTop: '1px solid var(--border-color)' }}>
        &copy; {new Date().getFullYear()} Network Security Phishing Detection Project. AI-Powered Analysis.
      </footer>
    </div>
  );
}

export default App;
