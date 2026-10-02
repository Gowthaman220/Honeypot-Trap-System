import React, { useState, useEffect } from 'react';
import { Search, Filter, RefreshCw, ChevronLeft, ChevronRight, ExternalLink, Download } from 'lucide-react';
import { EventItem, EventDetail, PaginatedEvents } from '../types';
import { api } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreBar } from '../components/RiskScoreBar';

interface LiveEventsPageProps {
  onSelectEvent: (event: EventDetail) => void;
  newEventsTrigger?: any;
}

export const LiveEventsPage: React.FC<LiveEventsPageProps> = ({ onSelectEvent, newEventsTrigger }) => {
  const [eventsData, setEventsData] = useState<PaginatedEvents>({
    items: [],
    total: 0,
    page: 1,
    page_size: 20,
    total_pages: 1
  });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [serviceFilter, setServiceFilter] = useState('');
  const [page, setPage] = useState(1);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await api.getEvents({
        page,
        page_size: 20,
        search: search.trim() || undefined,
        severity: severityFilter || undefined,
        service: serviceFilter || undefined
      });
      setEventsData(res);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, severityFilter, serviceFilter]);

  // When WebSocket fires a new event, refresh the first page
  useEffect(() => {
    if (newEventsTrigger && page === 1 && !search && !severityFilter && !serviceFilter) {
      fetchEvents();
    }
  }, [newEventsTrigger]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchEvents();
  };

  const handleRowClick = async (ev: EventItem) => {
    try {
      const detail = await api.getEventDetail(ev.event_id);
      onSelectEvent(detail);
    } catch {
      onSelectEvent({ ...ev, detections: [] });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Live Telemetry Ingestion Events
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Searchable, normalized security event logs with real-time risk scores
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchEvents}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs font-mono transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <a
            href={api.getExportCsvUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-mono transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </a>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 bg-[#111827] border border-slate-800 rounded-xl flex flex-col md:flex-row items-stretch md:items-center gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by Source IP, Service, Payload keywords..."
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </form>

        <div className="flex items-center space-x-3">
          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Service Filter */}
          <select
            value={serviceFilter}
            onChange={(e) => {
              setServiceFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-sky-500 font-mono"
          >
            <option value="">All Services</option>
            <option value="SSH">SSH Honeypot</option>
            <option value="HTTP">HTTP Honeypot</option>
            <option value="FTP">FTP Honeypot</option>
            <option value="TCP">Generic TCP Listener</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Time (UTC)</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Target Service</th>
                <th className="py-3 px-4">Port / Proto</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {eventsData.items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    {loading ? 'Fetching event stream...' : 'No telemetry events match query criteria.'}
                  </td>
                </tr>
              ) : (
                eventsData.items.map((ev) => (
                  <tr
                    key={ev.event_id}
                    onClick={() => handleRowClick(ev)}
                    className="hover:bg-slate-800/40 cursor-pointer transition group"
                  >
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-4 text-slate-200 font-bold whitespace-nowrap">
                      {ev.source_ip}
                    </td>
                    <td className="py-3 px-4 text-sky-400 font-medium">{ev.service}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {ev.destination_port}/{ev.protocol}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{ev.event_type}</td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={ev.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      <RiskScoreBar score={ev.risk_score} />
                    </td>
                    <td className="py-3 px-4 text-right text-slate-500 group-hover:text-sky-400">
                      <ExternalLink className="w-3.5 h-3.5 inline" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-4 py-3 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <div>
            Showing {eventsData.items.length} of {eventsData.total} events (Page {eventsData.page} of {eventsData.total_pages})
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 text-slate-300">{page}</span>
            <button
              onClick={() => setPage((p) => Math.min(eventsData.total_pages, p + 1))}
              disabled={page >= eventsData.total_pages}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
