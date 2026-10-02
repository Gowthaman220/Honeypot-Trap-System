import React, { useState, useEffect } from 'react';
import { FileText, Download, Calendar, RefreshCw, BarChart2, Shield } from 'lucide-react';
import { api } from '../services/api';
import { ReportSummary } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';

export const ReportsPage: React.FC = () => {
  const [period, setPeriod] = useState('daily');
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const data = await api.getReportSummary(period);
      setReport(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [period]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Academic Security Intelligence Reports
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Formal threat intelligence summaries suitable for project presentations and defense evaluations
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <a
            href={api.getExportCsvUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 rounded-lg text-xs font-mono transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </a>
          <a
            href={api.getExportJsonUrl()}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-mono transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </a>
        </div>
      </div>

      {/* Period Selector Bar */}
      <div className="p-4 bg-[#111827] border border-slate-800 rounded-xl flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Calendar className="w-4 h-4 text-sky-400" />
          <span className="text-xs font-mono text-slate-300 font-semibold uppercase">Reporting Horizon:</span>
          {['daily', 'weekly', 'custom'].map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`px-3 py-1 rounded-lg text-xs font-mono capitalize transition ${
                period === p
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/40 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        <button
          onClick={fetchReport}
          className="flex items-center space-x-1 text-xs text-slate-400 hover:text-slate-200 font-mono"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Generate</span>
        </button>
      </div>

      {report && (
        <div className="space-y-6">
          {/* Executive Narrative Callout */}
          <div className="p-5 rounded-xl bg-gradient-to-r from-sky-950/40 to-slate-900 border border-sky-500/30 space-y-2">
            <div className="flex items-center space-x-2 text-sky-400 text-xs font-mono font-bold uppercase">
              <Shield className="w-4 h-4" />
              <span>Executive Security Synopsis</span>
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {report.executive_summary}
            </p>
            <div className="text-[11px] font-mono text-slate-400 pt-1">
              Generated: {new Date(report.generated_at).toUTCString()} | Window: {new Date(report.start_date).toLocaleDateString()} – {new Date(report.end_date).toLocaleDateString()}
            </div>
          </div>

          {/* Metrics Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
              <span className="text-[11px] font-mono uppercase text-slate-400">Total Interactions</span>
              <p className="text-2xl font-bold font-mono text-white mt-1">{report.total_events}</p>
            </div>
            <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
              <span className="text-[11px] font-mono uppercase text-slate-400">Unique Threat Origins</span>
              <p className="text-2xl font-bold font-mono text-emerald-400 mt-1">{report.unique_sources}</p>
            </div>
            <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
              <span className="text-[11px] font-mono uppercase text-slate-400">Generated Incidents</span>
              <p className="text-2xl font-bold font-mono text-amber-400 mt-1">{report.total_alerts}</p>
            </div>
          </div>

          {/* Triggered Rules & Targeted Services */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold font-mono uppercase text-white">Detection Rules Fired</h3>
              <div className="space-y-2">
                {report.triggered_rules.map((r) => (
                  <div key={r.name} className="flex items-center justify-between text-xs font-mono p-2 bg-slate-900/60 rounded border border-slate-800">
                    <span className="text-slate-300">{r.name}</span>
                    <span className="text-sky-400 font-bold">{r.value} hits</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold font-mono uppercase text-white">Service Exposure Ratio</h3>
              <div className="space-y-2">
                {report.top_targeted_services.map((svc) => (
                  <div key={svc.service} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-300">{svc.service}</span>
                      <span className="text-slate-400">{svc.count} ({svc.percentage}%)</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-sky-500 rounded-full" style={{ width: `${svc.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
