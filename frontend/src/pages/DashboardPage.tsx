import React, { useState, useEffect } from 'react';
import {
  Activity,
  ShieldAlert,
  Users,
  AlertTriangle,
  Server,
  Bell,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  Radio
} from 'lucide-react';
import { DashboardSummary, EventItem, EventDetail } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreBar } from '../components/RiskScoreBar';

interface DashboardPageProps {
  onSelectEvent: (event: EventDetail) => void;
  onNavigateTab: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onSelectEvent, onNavigateTab }) => {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const summary = await api.getDashboardSummary();
      setData(summary);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
    const interval = setInterval(fetchDashboard, 15000); // Periodic 15s refresh
    return () => clearInterval(interval);
  }, []);

  const handleEventClick = async (event: EventItem) => {
    try {
      const detail = await api.getEventDetail(event.event_id);
      onSelectEvent(detail);
    } catch {
      // fallback
      onSelectEvent({ ...event, detections: [] });
    }
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3 text-slate-400">
          <RefreshCw className="w-8 h-8 animate-spin text-sky-400" />
          <p className="text-sm font-mono">Loading Security Operations Center Telemetry...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6">
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 flex items-center justify-between">
          <span>{error || 'Unable to connect to security telemetry backend.'}</span>
          <button
            onClick={fetchDashboard}
            className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 rounded-lg text-xs font-mono font-semibold"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const maxTimelineCount = Math.max(...data.timeline_24h.map((t) => t.count), 1);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Threat Monitoring & Telemetry Overview
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time capture, heuristic risk scoring, and honeypot service analytics
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchDashboard}
            title="Refresh Metrics"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs font-mono transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* Primary SOC Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        {/* Total Events */}
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Total Events</span>
            <Activity className="w-4 h-4 text-sky-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">{data.total_events.toLocaleString()}</p>
          <span className="text-[10px] text-slate-500 font-mono">Aggregated lifetime</span>
        </div>

        {/* Last 24 Hours */}
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">24h Activity</span>
            <TrendingUp className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-400">{data.events_last_24h.toLocaleString()}</p>
          <span className="text-[10px] text-slate-500 font-mono">Events in last 24h</span>
        </div>

        {/* Unique Source IPs */}
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Unique IPs</span>
            <Users className="w-4 h-4 text-indigo-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">{data.unique_ips.toLocaleString()}</p>
          <span className="text-[10px] text-slate-500 font-mono">Distinct originators</span>
        </div>

        {/* High / Critical Threats */}
        <div className="p-4 rounded-xl bg-[#111827] border border-red-500/20 bg-red-500/5">
          <div className="flex items-center justify-between text-red-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">High / Critical</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-red-400">{data.high_critical_events.toLocaleString()}</p>
          <span className="text-[10px] text-red-400/60 font-mono">Elevated risk events</span>
        </div>

        {/* Active Honeypot Decoys */}
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Active Decoys</span>
            <Server className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-emerald-400">{data.active_services} / 4</p>
          <span className="text-[10px] text-slate-500 font-mono">Listeners active</span>
        </div>

        {/* Active Alerts */}
        <div className="p-4 rounded-xl bg-[#111827] border border-amber-500/20 bg-amber-500/5">
          <div className="flex items-center justify-between text-amber-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Unresolved Alerts</span>
            <Bell className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-amber-400">{data.total_alerts}</p>
          <span className="text-[10px] text-amber-400/60 font-mono">Awaiting triage</span>
        </div>
      </div>

      {/* Middle Grid: Timeline & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-bold font-mono uppercase text-white">
                24-Hour Honeypot Activity Timeline
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">4-hour aggregation buckets</span>
          </div>

          <div className="h-44 flex items-end justify-between space-x-3 pt-6 pb-2 px-2 border-b border-slate-800">
            {data.timeline_24h.map((point, idx) => {
              const heightPct = Math.max(8, Math.round((point.count / maxTimelineCount) * 100));
              const highHeightPct = point.count > 0 ? Math.round((point.high_count / point.count) * 100) : 0;
              return (
                <div key={idx} className="flex-1 flex flex-col items-center group relative h-full justify-end">
                  {/* Tooltip */}
                  <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute -top-10 bg-slate-900 border border-slate-700 px-2 py-1 rounded text-[10px] font-mono text-slate-200 pointer-events-none whitespace-nowrap z-20">
                    {point.count} events ({point.high_count} high/critical)
                  </div>
                  {/* Bar */}
                  <div className="w-full max-w-[42px] bg-slate-800 rounded-t overflow-hidden relative" style={{ height: `${heightPct}%` }}>
                    <div className="absolute inset-0 bg-sky-500/40" />
                    {point.high_count > 0 && (
                      <div
                        className="absolute bottom-0 inset-x-0 bg-red-500/60"
                        style={{ height: `${highHeightPct}%` }}
                      />
                    )}
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 mt-2">{point.timestamp}</span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center justify-end space-x-4 text-xs font-mono text-slate-400">
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-sky-500/60 inline-block" />
              <span>Standard Events</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-red-500/60 inline-block" />
              <span>High / Critical</span>
            </div>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono uppercase text-white">Severity Classification</h3>
            <span className="text-xs text-slate-500 font-mono">Telemetry breakdown</span>
          </div>

          <div className="space-y-3 pt-2">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sevKey) => {
              const item = data.severity_distribution.find((s) => s.name === sevKey);
              const count = item ? item.value : 0;
              const total = data.total_events || 1;
              const pct = Math.round((count / total) * 100);

              const color =
                sevKey === 'CRITICAL' ? 'text-red-400 bg-red-500' :
                sevKey === 'HIGH' ? 'text-amber-400 bg-amber-500' :
                sevKey === 'MEDIUM' ? 'text-yellow-400 bg-yellow-400' :
                'text-emerald-400 bg-emerald-500';

              return (
                <div key={sevKey} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-semibold text-slate-300">{sevKey}</span>
                    <span className="text-slate-400">{count} ({pct}%)</span>
                  </div>
                  <div className="h-2 w-full bg-slate-800/80 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${color.split(' ')[1]}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80 text-[11px] text-slate-400">
            Severity levels are automatically derived from multi-factor heuristic threat detection rules.
          </div>
        </div>
      </div>

      {/* Bottom Grid: Top Targeted Services & Top Threat Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Targeted Services */}
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono uppercase text-white">Top Targeted Honeypot Services</h3>
            <button
              onClick={() => onNavigateTab('honeypots')}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1 font-mono"
            >
              <span>Manage Services</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {data.top_services.map((svc) => (
              <div key={svc.service} className="p-3 bg-slate-900/50 rounded-lg border border-slate-800/80 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="font-semibold text-slate-200">{svc.service}</span>
                  <span className="text-sky-400 font-bold">{svc.count} probes ({svc.percentage}%)</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-sky-500 rounded-full" style={{ width: `${svc.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Attacking Source IPs */}
        <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold font-mono uppercase text-white">Top Probing Source IPs</h3>
            <button
              onClick={() => onNavigateTab('threat_analysis')}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1 font-mono"
            >
              <span>Deep Analysis</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {data.top_source_ips.map((src) => (
              <div
                key={src.ip}
                className="p-3 bg-slate-900/50 rounded-lg border border-slate-800/80 flex items-center justify-between"
              >
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-slate-200">{src.ip}</span>
                    <SeverityBadge severity={src.highest_severity} size="sm" />
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Probed: {src.services.join(', ') || 'Various'}
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono font-semibold text-slate-300">{src.count} events</span>
                  <div className="mt-1">
                    <RiskScoreBar score={src.highest_score} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Live Recent Events Stream */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
            <h3 className="text-sm font-bold font-mono uppercase text-white">Real-Time Ingestion Feed</h3>
          </div>
          <button
            onClick={() => onNavigateTab('live_events')}
            className="text-xs text-sky-400 hover:text-sky-300 flex items-center space-x-1 font-mono"
          >
            <span>View Full Live Stream</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Source IP:Port</th>
                <th className="py-2.5 px-3">Service</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {data.recent_events.map((ev) => (
                <tr
                  key={ev.event_id}
                  onClick={() => handleEventClick(ev)}
                  className="hover:bg-slate-800/40 cursor-pointer transition group"
                >
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 text-slate-200 font-bold whitespace-nowrap">
                    {ev.source_ip}:{ev.source_port || ''}
                  </td>
                  <td className="py-2.5 px-3 text-sky-400">{ev.service}</td>
                  <td className="py-2.5 px-3 text-slate-300">{ev.event_type}</td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={ev.severity} size="sm" />
                  </td>
                  <td className="py-2.5 px-3">
                    <RiskScoreBar score={ev.risk_score} />
                  </td>
                  <td className="py-2.5 px-3 text-right text-slate-500 group-hover:text-sky-400">
                    <ExternalLink className="w-3.5 h-3.5 inline" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
