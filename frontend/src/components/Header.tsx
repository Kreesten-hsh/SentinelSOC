import React from 'react';
import { Shield, RefreshCw, Activity, Terminal } from 'lucide-react';

interface HeaderProps {
  onRefresh: () => void;
  onSeed: () => void;
  isRefreshing: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, onSeed, isRefreshing }) => {
  return (
    <header className="soc-header">
      <div className="brand-badge">
        <div className="brand-logo">
          <Shield size={22} />
        </div>
        <div>
          <h1 className="brand-title">SentinelSOC</h1>
          <p className="brand-subtitle">Autonomous Tier-2 Investigation Agent</p>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.35rem 0.75rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '9999px', fontSize: '0.75rem', color: '#34d399', fontWeight: 600 }}>
          <Activity size={14} className="animate-pulse" />
          <span>Agent Live • 7-Step Reasoning</span>
        </div>

        <button className="btn btn-secondary" onClick={onRefresh} disabled={isRefreshing} title="Refresh Alerts">
          <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
          <span>Sync</span>
        </button>

        <button className="btn btn-secondary" onClick={onSeed} title="Reload BOTS v1 Scenario Dataset">
          <Terminal size={14} />
          <span>Reset Scenarios</span>
        </button>
      </div>
    </header>
  );
};
