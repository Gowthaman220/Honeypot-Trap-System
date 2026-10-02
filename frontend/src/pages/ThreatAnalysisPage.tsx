import React, { useState, useEffect } from 'react';
import { Shield, FileSearch, AlertCircle, RefreshCw, Cpu, Database } from 'lucide-react';
import { api } from '../services/api';
import { DetectionItem, TopSourceIP } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreBar } from '../components/RiskScoreBar';

export const ThreatAnalysisPage: React.FC = () => {
  const [detections, setDetections] = useState<DetectionItem[]>([]);
  const [topIps, setTopIps] = useState<TopSourceIP[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchThreatData = async () => {
    setLoading(true);
    try {
      const [dets, summary] = await Promise.all([
        api.getDetections(),
        api.getDashboardSummary()
      ]);
      setDetections(dets);
      setTopIps(summary.top_source_ips);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, []);

  // Compute rule counts
  const ruleCounts: Record<string, { name: string; severity: string; count: number; desc: string }> = {};
  detections.forEach((d) => {
    if (!ruleCounts[d.rule_id]) {
      ruleCounts[d.rule_id] = {
        name: d.rule_name,
        severity: d.severity,
        count: 0,
        desc: d.description
      };
    }
    ruleCounts[d.rule_id].count++;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Threat Intelligence & Detection Rule Analytics
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlation analysis, rule triggers, and persistent adversary behavioral profiles
          </p>
        </div>
        <button
          onClick={fetchThreatData}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Analysis</span>
        </button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Active Rules</span>
            <Cpu className="w-4 h-4 text-sky-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">8 Engine Rules</p>
          <span className="text-[10px] text-slate-500 font-mono">Real-time heuristic evaluation</span>
        </div>

        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Total Rule Matches</span>
            <FileSearch className="w-4 h-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-amber-400">{detections.length}</p>
          <span className="text-[10px] text-slate-500 font-mono">Detections recorded</span>
        </div>

        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-mono uppercase font-semibold">Correlated Adversaries</span>
            <Database className="w-4 h-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold font-mono text-white">{topIps.length} Tracked Hosts</p>
          <span className="text-[10px] text-slate-500 font-mono">Aggregated IP profiles</span>
        </div>
      </div>

      {/* Detection Rules Performance Table */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4 shadow-xl">
        <h3 className="text-sm font-bold font-mono uppercase text-white">
          Detection Rules Trigger Frequency
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Rule ID</th>
                <th className="py-2.5 px-4">Rule Name</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Description</th>
                <th className="py-2.5 px-4 text-right">Trigger Count</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {Object.keys(ruleCounts).length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    No detection rules triggered yet.
                  </td>
                </tr>
              ) : (
                Object.entries(ruleCounts).map(([ruleId, info]) => (
                  <tr key={ruleId} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-bold text-sky-400">{ruleId}</td>
                    <td className="py-3 px-4 text-slate-200 font-semibold">{info.name}</td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={info.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] max-w-md">{info.desc}</td>
                    <td className="py-3 px-4 text-right font-bold text-slate-200">{info.count}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Persistent Source IP Threat Profiles */}
      <div className="p-5 rounded-xl bg-[#111827] border border-slate-800 space-y-4 shadow-xl">
        <h3 className="text-sm font-bold font-mono uppercase text-white">
          Persistent Adversary Profiles & Reconnaissance Footprints
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Source Host IP</th>
                <th className="py-2.5 px-4">Targeted Honeypot Decoys</th>
                <th className="py-2.5 px-4">Threat Level</th>
                <th className="py-2.5 px-4">Peak Risk Score</th>
                <th className="py-2.5 px-4 text-right">Total Interactions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {topIps.map((src) => (
                <tr key={src.ip} className="hover:bg-slate-800/40">
                  <td className="py-3 px-4 font-bold text-slate-200">{src.ip}</td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {src.services.map((svc) => (
                        <span
                          key={svc}
                          className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-sky-300 border border-slate-700"
                        >
                          {svc}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={src.highest_severity} size="sm" />
                  </td>
                  <td className="py-3 px-4">
                    <RiskScoreBar score={src.highest_score} />
                  </td>
                  <td className="py-3 px-4 text-right font-bold text-slate-200">{src.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
