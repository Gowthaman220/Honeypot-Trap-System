import React, { useState, useEffect } from 'react';
import { Bell, CheckCircle, Clock, ShieldAlert, Filter, RefreshCw, MessageSquare } from 'lucide-react';
import { api } from '../services/api';
import { AlertItem } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

interface AlertsPageProps {
  onAlertStatusChange?: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onAlertStatusChange }) => {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const data = await api.getAlerts(statusFilter || undefined, severityFilter || undefined);
      setAlerts(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [statusFilter, severityFilter]);

  const handleUpdateStatus = async (alertId: string, newStatus: string) => {
    setActionLoading(alertId);
    try {
      const notes = prompt(`Enter resolution / response notes for alert (optional):`, '');
      await api.updateAlert(alertId, newStatus, notes || undefined);
      await fetchAlerts();
      if (onAlertStatusChange) onAlertStatusChange();
    } catch (err: any) {
      alert(`Failed to update alert: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Security Incident Alerts & Triage Center
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated alerts triggered by High and Critical threat vectors
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-4 bg-[#111827] border border-slate-800 rounded-xl flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <span className="text-xs font-mono text-slate-400 font-semibold uppercase flex items-center space-x-1">
            <Filter className="w-3.5 h-3.5" />
            <span>Filter Alerts:</span>
          </span>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Statuses</option>
            <option value="NEW">New (Active)</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>
        </div>

        <span className="text-xs font-mono text-slate-500">
          {alerts.length} incident record{alerts.length === 1 ? '' : 's'}
        </span>
      </div>

      {/* Alerts List */}
      <div className="space-y-3">
        {alerts.length === 0 ? (
          <div className="p-12 text-center bg-[#111827] border border-slate-800 rounded-xl text-slate-500 font-mono text-xs">
            {loading ? 'Retrieving security incident alerts...' : 'No incident alerts match filter criteria.'}
          </div>
        ) : (
          alerts.map((alert) => {
            const isNew = alert.status === 'NEW';
            const isAck = alert.status === 'ACKNOWLEDGED';
            const isResolved = alert.status === 'RESOLVED';

            return (
              <div
                key={alert.alert_id}
                className={`p-4 rounded-xl border bg-[#111827] transition flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                  isNew
                    ? 'border-red-500/40 bg-red-500/5'
                    : isAck
                    ? 'border-amber-500/40 bg-amber-500/5'
                    : 'border-slate-800'
                }`}
              >
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex items-center space-x-3">
                    <SeverityBadge severity={alert.severity} size="sm" />
                    <span className="text-sm font-bold font-mono text-white">{alert.title}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                        isNew
                          ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                          : isAck
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      }`}
                    >
                      {alert.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 font-mono">
                    Targeted IP: <span className="text-slate-200 font-semibold">{alert.source_ip}</span> | Time:{' '}
                    {new Date(alert.timestamp).toUTCString()}
                  </p>

                  {alert.notes && (
                    <div className="text-xs font-mono text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-800 flex items-start space-x-1.5">
                      <MessageSquare className="w-3.5 h-3.5 text-sky-400 mt-0.5 flex-shrink-0" />
                      <span>{alert.notes}</span>
                    </div>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex items-center space-x-2 flex-shrink-0">
                  {isNew && (
                    <button
                      onClick={() => handleUpdateStatus(alert.alert_id, 'ACKNOWLEDGED')}
                      disabled={actionLoading === alert.alert_id}
                      className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border border-amber-500/40 text-xs font-mono font-semibold transition"
                    >
                      Acknowledge
                    </button>
                  )}
                  {!isResolved && (
                    <button
                      onClick={() => handleUpdateStatus(alert.alert_id, 'RESOLVED')}
                      disabled={actionLoading === alert.alert_id}
                      className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/40 text-xs font-mono font-semibold transition"
                    >
                      Resolve
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
