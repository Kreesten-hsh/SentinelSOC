import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle, Clock } from 'lucide-react';
import type { AlertSummary } from '../types';

interface AlertQueueProps {
  alerts: AlertSummary[];
  selectedAlertId: string | null;
  onSelectAlert: (id: string) => void;
  isLoading: boolean;
}

export const AlertQueue: React.FC<AlertQueueProps> = ({
  alerts,
  selectedAlertId,
  onSelectAlert,
  isLoading,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      a.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.source.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'all' || a.severity?.toLowerCase() === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="card-panel">
      <div className="panel-header">
        <div className="panel-title">
          <ShieldAlert size={18} style={{ color: 'var(--cyber-blue)' }} />
          <span>Triage Queue ({filteredAlerts.length})</span>
        </div>
      </div>

      <div style={{ padding: '0.75rem 1rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', gap: '0.5rem' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={14} style={{ position: 'absolute', left: '0.65rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Filter by ID, host, attacker..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '0.45rem 0.65rem 0.45rem 2rem',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
              outline: 'none',
            }}
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{
            padding: '0.45rem 0.65rem',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--text-primary)',
            fontSize: '0.8rem',
            outline: 'none',
          }}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="panel-body">
        {isLoading ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            Loading alerts from SIEM...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            No matching alerts found.
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isSelected = alert.id === selectedAlertId;
            const sevClass = alert.severity || 'low';

            return (
              <div
                key={alert.id}
                className={`alert-card-item ${sevClass} ${isSelected ? 'active' : ''}`}
                onClick={() => onSelectAlert(alert.id)}
              >
                <div className="alert-card-header">
                  <span className="alert-id">{alert.id}</span>
                  <span className="alert-time">
                    {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>

                <div className="alert-title">{alert.title}</div>

                <div className="alert-meta-tags">
                  {alert.severity ? (
                    <span className={`badge badge-${alert.severity}`}>
                      {alert.severity}
                    </span>
                  ) : (
                    <span className="badge badge-status-pending">Unscored</span>
                  )}

                  {alert.status === 'completed' ? (
                    <span className="badge badge-status-completed">
                      <CheckCircle size={10} />
                      {alert.verdict ? alert.verdict.replace('_', ' ') : 'Investigated'}
                    </span>
                  ) : (
                    <span className="badge badge-status-pending">
                      <Clock size={10} />
                      Pending
                    </span>
                  )}

                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    {alert.source}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
