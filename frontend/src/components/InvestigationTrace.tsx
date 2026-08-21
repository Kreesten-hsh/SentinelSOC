import React from 'react';
import { Play, FileText, CheckCircle, AlertTriangle, XCircle, Terminal, Layers, Globe } from 'lucide-react';
import type { AlertDetail } from '../types';

interface InvestigationTraceProps {
  alert: AlertDetail | null;
  onInvestigate: (id: string) => void;
  onViewReport: (id: string) => void;
  isInvestigating: boolean;
}

export const InvestigationTrace: React.FC<InvestigationTraceProps> = ({
  alert,
  onInvestigate,
  onViewReport,
  isInvestigating,
}) => {
  if (!alert) {
    return (
      <div className="card-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        <div style={{ textAlign: 'center' }}>
          <Layers size={40} style={{ opacity: 0.3, marginBottom: '1rem' }} />
          <p>Select an alert from the triage queue to view details or launch investigation.</p>
        </div>
      </div>
    );
  }

  const hasInvestigation = !!alert.investigation;
  const inv = alert.investigation;

  return (
    <div className="card-panel">
      <div className="panel-header">
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--cyber-blue)', fontWeight: 600 }}>
            {alert.id} • {alert.source}
          </div>
          <div className="panel-title" style={{ marginTop: '0.2rem' }}>
            {alert.title}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem' }}>
          {!hasInvestigation && (
            <button
              className="btn btn-primary"
              onClick={() => onInvestigate(alert.id)}
              disabled={isInvestigating}
            >
              <Play size={14} />
              <span>{isInvestigating ? 'Agent Investigating...' : 'Investigate'}</span>
            </button>
          )}

          {hasInvestigation && (
            <button className="btn btn-secondary" onClick={() => onViewReport(alert.id)}>
              <FileText size={14} />
              <span>Full SOC Report</span>
            </button>
          )}
        </div>
      </div>

      <div className="panel-body">
        {/* Severity & Verdict Summary Banner */}
        {hasInvestigation && inv && (
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '1rem',
              marginBottom: '1.5rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Autonomous Verdict
              </div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {inv.verdict === 'true_positive' && <XCircle size={20} color="var(--sev-critical)" />}
                {inv.verdict === 'false_positive' && <CheckCircle size={20} color="var(--sev-low)" />}
                {inv.verdict === 'suspicious' && <AlertTriangle size={20} color="var(--sev-medium)" />}
                <span>{inv.verdict ? inv.verdict.toUpperCase().replace('_', ' ') : 'PENDING'}</span>
              </div>
            </div>

            {inv.severity_score && (
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Calibrated Severity
                </div>
                <div style={{ fontSize: '1.2rem', fontWeight: 800, color: inv.severity_score.severity === 'critical' ? 'var(--sev-critical)' : inv.severity_score.severity === 'medium' ? 'var(--sev-medium)' : 'var(--sev-low)' }}>
                  {inv.severity_score.severity.toUpperCase()} ({inv.severity_score.final_score.toFixed(1)}/100)
                </div>
              </div>
            )}
          </div>
        )}

        {/* 7-Step Reasoning Trace */}
        {hasInvestigation && inv ? (
          <div>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Terminal size={16} color="var(--cyber-blue)" />
              <span>Multi-Step Autonomous Reasoning Trace ({inv.steps.length} Steps)</span>
            </div>

            <div style={{ marginTop: '1rem' }}>
              {inv.steps.map((step) => (
                <div key={step.step_number} className="step-item">
                  <div className="step-number-bullet">{step.step_number}</div>
                  <div className="step-card">
                    <div className="step-header">
                      <div className="step-title">{step.action}</div>
                      <span className="step-tool-tag">{step.tool_used}</span>
                    </div>

                    <div className="step-reasoning">
                      <strong>Reasoning:</strong> {step.reasoning}
                    </div>

                    <div className="step-result-box">
                      {step.result_summary}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
            <Globe size={40} style={{ opacity: 0.3, marginBottom: '1rem' }} />
            <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem' }}>Awaiting Agent Triage</h3>
            <p style={{ maxWidth: '400px', margin: '0 auto 1.5rem', fontSize: '0.85rem' }}>
              Click "Investigate" to trigger the multi-step autonomous agent: IOC extraction, log queries, cross-source correlation, threat intelligence lookup, and ML severity scoring.
            </p>
            <button
              className="btn btn-primary"
              onClick={() => onInvestigate(alert.id)}
              disabled={isInvestigating}
            >
              <Play size={14} />
              <span>Launch Autonomous Triage</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
