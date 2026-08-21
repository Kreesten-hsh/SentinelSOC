import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { StatsOverview } from './components/StatsOverview';
import { AlertQueue } from './components/AlertQueue';
import { InvestigationTrace } from './components/InvestigationTrace';
import { ReportModal } from './components/ReportModal';
import {
  fetchAlerts,
  fetchStats,
  fetchAlert,
  triggerInvestigation,
  fetchReport,
  seedAlerts,
} from './api';
import type { AlertSummary, AlertDetail, StatsResponse, ReportData } from './types';

export const App: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedAlertDetail, setSelectedAlertDetail] = useState<AlertDetail | null>(null);
  const [activeReport, setActiveReport] = useState<ReportData | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isInvestigating, setIsInvestigating] = useState(false);

  const loadData = async (initial = false) => {
    if (initial) setIsLoading(true);
    else setIsRefreshing(true);

    try {
      const [alertsData, statsData] = await Promise.all([fetchAlerts(), fetchStats()]);
      setAlerts(alertsData);
      setStats(statsData);

      // Auto-select first alert if none selected
      if (!selectedAlertId && alertsData.length > 0) {
        setSelectedAlertId(alertsData[0].id);
        const detail = await fetchAlert(alertsData[0].id);
        setSelectedAlertDetail(detail);
      } else if (selectedAlertId) {
        const detail = await fetchAlert(selectedAlertId);
        setSelectedAlertDetail(detail);
      }
    } catch (err) {
      console.error('Error fetching SOC data:', err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, []);

  const handleSelectAlert = async (id: string) => {
    setSelectedAlertId(id);
    try {
      const detail = await fetchAlert(id);
      setSelectedAlertDetail(detail);
    } catch (err) {
      console.error(`Error fetching detail for alert ${id}:`, err);
    }
  };

  const handleInvestigate = async (id: string) => {
    setIsInvestigating(true);
    try {
      const updatedDetail = await triggerInvestigation(id);
      setSelectedAlertDetail(updatedDetail);
      // Refresh alert queue and stats
      const [alertsData, statsData] = await Promise.all([fetchAlerts(), fetchStats()]);
      setAlerts(alertsData);
      setStats(statsData);
    } catch (err) {
      console.error(`Error running investigation for ${id}:`, err);
    } finally {
      setIsInvestigating(false);
    }
  };

  const handleViewReport = async (id: string) => {
    try {
      const report = await fetchReport(id);
      setActiveReport(report);
    } catch (err) {
      console.error(`Error loading report for ${id}:`, err);
    }
  };

  const handleSeed = async () => {
    setIsRefreshing(true);
    try {
      await seedAlerts(true);
      await loadData(true);
    } catch (err) {
      console.error('Error re-seeding alerts:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  return (
    <div className="app-container">
      <Header
        onRefresh={() => loadData(false)}
        onSeed={handleSeed}
        isRefreshing={isRefreshing}
      />

      <main className="main-content">
        <StatsOverview stats={stats} />

        <div className="workspace-grid">
          <AlertQueue
            alerts={alerts}
            selectedAlertId={selectedAlertId}
            onSelectAlert={handleSelectAlert}
            isLoading={isLoading}
          />

          <InvestigationTrace
            alert={selectedAlertDetail}
            onInvestigate={handleInvestigate}
            onViewReport={handleViewReport}
            isInvestigating={isInvestigating}
          />
        </div>
      </main>

      <ReportModal
        report={activeReport}
        onClose={() => setActiveReport(null)}
      />
    </div>
  );
};

export default App;
