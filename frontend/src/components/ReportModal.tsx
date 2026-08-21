import React from 'react';
import ReactMarkdown from 'react-markdown';
import { X, Download, ShieldCheck } from 'lucide-react';
import type { ReportData } from '../types';

interface ReportModalProps {
  report: ReportData | null;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ report, onClose }) => {
  if (!report) return null;

  const handleDownload = () => {
    const blob = new Blob([report.markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.alert_id}_investigation_report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="panel-header" style={{ padding: '1rem 1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldCheck size={20} style={{ color: 'var(--cyber-blue)' }} />
            <span style={{ fontWeight: 700, fontSize: '1rem' }}>{report.title}</span>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-secondary" onClick={handleDownload}>
              <Download size={14} />
              <span>Export Markdown</span>
            </button>

            <button className="btn btn-secondary" onClick={onClose} style={{ padding: '0.4rem' }}>
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="modal-body">
          <ReactMarkdown>{report.markdown}</ReactMarkdown>
        </div>
      </div>
    </div>
  );
};
