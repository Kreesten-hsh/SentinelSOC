import type { AlertDetail, AlertSummary, ReportData, StatsResponse } from './types';

const API_BASE = '/api';

export async function fetchAlerts(severity?: string, status?: string): Promise<AlertSummary[]> {
  const params = new URLSearchParams();
  if (severity) params.append('severity', severity);
  if (status) params.append('status', status);

  const url = `${API_BASE}/alerts${params.toString() ? `?${params.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  return res.json();
}

export async function fetchStats(): Promise<StatsResponse> {
  const res = await fetch(`${API_BASE}/alerts/stats`);
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.statusText}`);
  return res.json();
}

export async function fetchAlert(id: string): Promise<AlertDetail> {
  const res = await fetch(`${API_BASE}/alerts/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch alert ${id}: ${res.statusText}`);
  return res.json();
}

export async function triggerInvestigation(id: string): Promise<AlertDetail> {
  const res = await fetch(`${API_BASE}/alerts/${id}/investigate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to trigger investigation: ${res.statusText}`);
  return fetchAlert(id);
}

export async function fetchReport(id: string): Promise<ReportData> {
  const res = await fetch(`${API_BASE}/alerts/${id}/report`);
  if (!res.ok) throw new Error(`Failed to fetch report for ${id}: ${res.statusText}`);
  return res.json();
}

export async function seedAlerts(force = false): Promise<void> {
  const res = await fetch(`${API_BASE}/alerts/seed?force=${force}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to seed alerts: ${res.statusText}`);
}
