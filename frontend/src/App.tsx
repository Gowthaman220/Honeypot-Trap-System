import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { EventDetailModal } from './components/EventDetailModal';
import { Login } from './pages/Login';
import { DashboardPage } from './pages/DashboardPage';
import { LiveEventsPage } from './pages/LiveEventsPage';
import { ThreatAnalysisPage } from './pages/ThreatAnalysisPage';
import { HoneypotsPage } from './pages/HoneypotsPage';
import { AlertsPage } from './pages/AlertsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { useWebSocket, WebSocketMessage } from './services/websocket';
import { EventDetail } from './types';
import { api } from './services/api';

export function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return !!localStorage.getItem('honeypot_token');
  });
  const [currentUser, setCurrentUser] = useState<string>(() => {
    try {
      const u = localStorage.getItem('honeypot_user');
      return u ? JSON.parse(u).username : 'Admin';
    } catch {
      return 'Admin';
    }
  });

  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [selectedEvent, setSelectedEvent] = useState<EventDetail | null>(null);
  const [newAlertsCount, setNewAlertsCount] = useState<number>(0);
  const [wsEventTrigger, setWsEventTrigger] = useState<any>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Sync auth state
  useEffect(() => {
    const handleAuthChange = () => {
      const token = localStorage.getItem('honeypot_token');
      setIsAuthenticated(!!token);
      if (token) {
        try {
          const u = localStorage.getItem('honeypot_user');
          setCurrentUser(u ? JSON.parse(u).username : 'Admin');
        } catch {}
      }
    };
    window.addEventListener('auth_change', handleAuthChange);
    return () => window.removeEventListener('auth_change', handleAuthChange);
  }, []);

  // Fetch initial alerts count
  const refreshAlertCount = useCallback(async () => {
    if (!isAuthenticated) return;
    try {
      const alerts = await api.getAlerts('NEW');
      setNewAlertsCount(alerts.length);
    } catch {}
  }, [isAuthenticated]);

  useEffect(() => {
    if (isAuthenticated) {
      refreshAlertCount();
    }
  }, [isAuthenticated, refreshAlertCount]);

  // Handle incoming WebSocket messages
  const handleWsMessage = useCallback((msg: WebSocketMessage) => {
    if (msg.type === 'NEW_EVENT') {
      setWsEventTrigger(msg.data);
    } else if (msg.type === 'NEW_ALERT') {
      setNewAlertsCount((prev) => prev + 1);
      setToastMessage(`CRITICAL ALERT: ${msg.data.title}`);
      setTimeout(() => setToastMessage(null), 5000);
    }
  }, []);

  const { isConnected } = useWebSocket(handleWsMessage);

  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Real-time Incident Notification Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-red-950/90 border border-red-500/80 text-red-200 px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-3 animate-bounce font-mono text-xs">
          <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-ping" />
          <span>{toastMessage}</span>
          <button
            onClick={() => setToastMessage(null)}
            className="ml-2 text-red-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Top Navbar */}
      <Navbar wsConnected={isConnected} username={currentUser} />

      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          newAlertsCount={newAlertsCount}
        />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto bg-[#0b0f19] pb-12">
          {currentTab === 'dashboard' && (
            <DashboardPage
              onSelectEvent={setSelectedEvent}
              onNavigateTab={setCurrentTab}
            />
          )}
          {currentTab === 'live_events' && (
            <LiveEventsPage
              onSelectEvent={setSelectedEvent}
              newEventsTrigger={wsEventTrigger}
            />
          )}
          {currentTab === 'threat_analysis' && <ThreatAnalysisPage />}
          {currentTab === 'honeypots' && <HoneypotsPage />}
          {currentTab === 'alerts' && (
            <AlertsPage onAlertStatusChange={refreshAlertCount} />
          )}
          {currentTab === 'reports' && <ReportsPage />}
          {currentTab === 'settings' && <SettingsPage />}
        </main>
      </div>

      {/* Deep Event Telemetry Modal Inspector */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
}

export default App;
