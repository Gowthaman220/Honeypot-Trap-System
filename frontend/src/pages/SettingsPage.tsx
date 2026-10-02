import React, { useState, useEffect } from 'react';
import { Settings, Sliders, Shield, RefreshCw, Save, Check } from 'lucide-react';
import { api } from '../services/api';
import { SystemSettings } from '../types';

export const SettingsPage: React.FC = () => {
  const [settingsData, setSettingsData] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [weights, setWeights] = useState({
    repeated_attempts: 10,
    multi_service: 20,
    high_frequency: 20,
    suspicious_pattern: 20,
    known_indicator: 30
  });

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const data = await api.getSettings();
      setSettingsData(data);
      setWeights(data.risk_weights);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleToggleRule = async (ruleId: string, currentStatus: boolean) => {
    try {
      await api.toggleRule(ruleId, !currentStatus);
      if (settingsData) {
        setSettingsData({
          ...settingsData,
          detection_rules: settingsData.detection_rules.map((r) =>
            r.rule_id === ruleId ? { ...r, enabled: !currentStatus } : r
          )
        });
      }
    } catch (err: any) {
      alert(`Error toggling rule: ${err.message}`);
    }
  };

  const handleSaveWeights = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavedMsg(null);
    try {
      await api.updateRiskWeights(weights);
      setSavedMsg('Risk scoring heuristic weights updated successfully.');
      setTimeout(() => setSavedMsg(null), 3000);
    } catch (err: any) {
      alert(`Error updating weights: ${err.message}`);
    }
  };

  if (!settingsData) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 animate-spin text-sky-400" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
          System Configuration & Detection Engine Settings
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Tune threat detection sensitivity thresholds and heuristic risk factor weighting
        </p>
      </div>

      {savedMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono rounded-lg flex items-center space-x-2">
          <Check className="w-4 h-4 flex-shrink-0" />
          <span>{savedMsg}</span>
        </div>
      )}

      {/* Detection Rules Toggle Settings */}
      <div className="p-5 bg-[#111827] border border-slate-800 rounded-xl space-y-4 shadow-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold font-mono uppercase text-white">
              Detection Rules Activation Matrix
            </h3>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            {settingsData.detection_rules.filter((r) => r.enabled).length} of {settingsData.detection_rules.length} active
          </span>
        </div>

        <div className="divide-y divide-slate-800">
          {settingsData.detection_rules.map((rule) => (
            <div key={rule.rule_id} className="py-3 flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-sky-400">{rule.rule_id}</span>
                  <span className="text-sm font-semibold text-slate-200">{rule.name}</span>
                </div>
                <p className="text-xs text-slate-400">{rule.description}</p>
              </div>

              <button
                type="button"
                onClick={() => handleToggleRule(rule.rule_id, rule.enabled)}
                className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  rule.enabled ? 'bg-sky-600' : 'bg-slate-800'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                    rule.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Risk Scoring Heuristic Weightings */}
      <div className="p-5 bg-[#111827] border border-slate-800 rounded-xl space-y-4 shadow-xl">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold font-mono uppercase text-white">
            Explainable Risk Scoring Heuristic Weights
          </h3>
        </div>

        <form onSubmit={handleSaveWeights} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Repeated Attempts (+pts)
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={weights.repeated_attempts}
                onChange={(e) => setWeights({ ...weights, repeated_attempts: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Multiple Services Targeted (+pts)
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={weights.multi_service}
                onChange={(e) => setWeights({ ...weights, multi_service: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                High Request Frequency / Burst (+pts)
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={weights.high_frequency}
                onChange={(e) => setWeights({ ...weights, high_frequency: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Suspicious Request Pattern (+pts)
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={weights.suspicious_pattern}
                onChange={(e) => setWeights({ ...weights, suspicious_pattern: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Known Malicious Indicator / Test Token (+pts)
              </label>
              <input
                type="number"
                min="0"
                max="50"
                value={weights.known_indicator}
                onChange={(e) => setWeights({ ...weights, known_indicator: parseInt(e.target.value) || 0 })}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div className="pt-2 flex justify-end">
            <button
              type="submit"
              className="flex items-center space-x-1.5 px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-mono font-bold transition shadow-lg shadow-sky-600/20"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Update Scoring Weights</span>
            </button>
          </div>
        </form>
      </div>

      {/* Honeypot Ports Overview */}
      <div className="p-5 bg-[#111827] border border-slate-800 rounded-xl space-y-3">
        <h3 className="text-sm font-bold font-mono uppercase text-white">Configured Network Ports</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
            <span className="text-slate-500">SSH Honeypot</span>
            <p className="text-slate-200 font-bold mt-1">Port {settingsData.honeypot_ports.ssh}</p>
          </div>
          <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
            <span className="text-slate-500">HTTP Honeypot</span>
            <p className="text-slate-200 font-bold mt-1">Port {settingsData.honeypot_ports.http}</p>
          </div>
          <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
            <span className="text-slate-500">FTP Honeypot</span>
            <p className="text-slate-200 font-bold mt-1">Port {settingsData.honeypot_ports.ftp}</p>
          </div>
          <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
            <span className="text-slate-500">Generic TCP Listener</span>
            <p className="text-slate-200 font-bold mt-1">Port {settingsData.honeypot_ports.tcp}</p>
          </div>
        </div>
      </div>
    </div>
  );
};
