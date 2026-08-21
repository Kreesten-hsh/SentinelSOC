import React from 'react';
import { ShieldAlert, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import type { StatsResponse } from '../types';

interface StatsOverviewProps {
  stats: StatsResponse | null;
}

export const StatsOverview: React.FC<StatsOverviewProps> = ({ stats }) => {
  if (!stats) return null;

  return (
    <div className="stats-grid">
      <div className="stat-card">
        <div>
          <div className="stat-value">{stats.total_alerts}</div>
          <div className="stat-label">Total SIEM Alerts</div>
        </div>
        <div style={{ color: 'var(--cyber-blue)' }}>
          <ShieldAlert size={26} />
        </div>
      </div>

      <div className="stat-card" style={{ borderColor: 'var(--sev-critical-border)' }}>
        <div>
          <div className="stat-value" style={{ color: 'var(--sev-critical)' }}>
            {stats.critical_alerts}
          </div>
          <div className="stat-label">Critical Threat Alerts</div>
        </div>
        <div style={{ color: 'var(--sev-critical)' }}>
          <XCircle size={26} />
        </div>
      </div>

      <div className="stat-card">
        <div>
          <div className="stat-value" style={{ color: '#60a5fa' }}>
            {stats.true_positives}
          </div>
          <div className="stat-label">Confirmed True Positives</div>
        </div>
        <div style={{ color: '#60a5fa' }}>
          <AlertTriangle size={26} />
        </div>
      </div>

      <div className="stat-card" style={{ borderColor: 'var(--sev-low-border)' }}>
        <div>
          <div className="stat-value" style={{ color: 'var(--sev-low)' }}>
            {stats.false_positives}
          </div>
          <div className="stat-label">Discarded False Positives</div>
        </div>
        <div style={{ color: 'var(--sev-low)' }}>
          <CheckCircle2 size={26} />
        </div>
      </div>
    </div>
  );
};
