import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, Cpu, Terminal, FileText, Info } from 'lucide-react';
import { EventDetail } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { RiskScoreBar } from './RiskScoreBar';

interface EventDetailModalProps {
  event: EventDetail | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const copyPayload = () => {
    if (event.raw_payload) {
      navigator.clipboard.writeText(event.raw_payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  let metadataObj: any = {};
  try {
    if (event.metadata_json) {
      metadataObj = JSON.parse(event.metadata_json);
    }
  } catch {}

  const scoringFactors = metadataObj.scoring_factors || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#111827] border border-slate-700/80 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-white font-mono">Event Telemetry Inspector</h3>
                <SeverityBadge severity={event.severity} />
              </div>
              <p className="text-xs text-slate-400 font-mono">{event.event_id}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* High-level Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-900/40 p-4 rounded-lg border border-slate-800">
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase">Source IP & Port</span>
              <p className="text-sm font-semibold font-mono text-slate-200">
                {event.source_ip}:{event.source_port || 'N/A'}
              </p>
            </div>
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase">Target Service</span>
              <p className="text-sm font-semibold font-mono text-sky-400">
                {event.service} ({event.destination_port}/{event.protocol})
              </p>
            </div>
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase">Event Type</span>
              <p className="text-sm font-semibold font-mono text-slate-200">{event.event_type}</p>
            </div>
            <div>
              <span className="text-[11px] font-mono text-slate-400 uppercase">Risk Score</span>
              <div className="mt-1">
                <RiskScoreBar score={event.risk_score} />
              </div>
            </div>
          </div>

          {/* Triggered Detections */}
          <div>
            <h4 className="text-xs font-mono uppercase text-slate-400 font-bold mb-2 flex items-center space-x-1.5">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Triggered Detection Rules ({event.detections?.length || 0})</span>
            </h4>
            {event.detections && event.detections.length > 0 ? (
              <div className="space-y-2">
                {event.detections.map((det) => (
                  <div
                    key={det.id}
                    className="p-3 rounded-lg border border-slate-800 bg-slate-900/50 flex flex-col space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-1.5 py-0.5 text-xs font-mono font-bold rounded bg-slate-800 text-slate-300">
                          {det.rule_id}
                        </span>
                        <span className="text-sm font-semibold text-slate-200">{det.rule_name}</span>
                      </div>
                      <SeverityBadge severity={det.severity} size="sm" />
                    </div>
                    <p className="text-xs text-slate-400">{det.description}</p>
                    {det.evidence && (
                      <div className="p-2 rounded bg-slate-950/60 border border-slate-800/80 text-xs font-mono text-amber-300/90">
                        {det.evidence}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/20 text-xs text-slate-500 font-mono">
                No automated threat detection rules triggered for this baseline event.
              </div>
            )}
          </div>

          {/* Explainable Risk Scoring Factors */}
          {scoringFactors.length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 font-bold mb-2 flex items-center space-x-1.5">
                <Info className="w-4 h-4 text-sky-400" />
                <span>Explainable Risk Scoring Breakdown</span>
              </h4>
              <div className="bg-slate-900/50 border border-slate-800 rounded-lg divide-y divide-slate-800">
                {scoringFactors.map((f: any, idx: number) => (
                  <div key={idx} className="p-2.5 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-300">{f.factor}: <span className="text-slate-500">{f.detail}</span></span>
                    <span className="text-sky-400 font-bold">+{f.contribution} pts</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw Payload & Headers */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-slate-400" />
                <span>Raw Captured Payload</span>
              </h4>
              {event.raw_payload && (
                <button
                  onClick={copyPayload}
                  className="flex items-center space-x-1 text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 border border-slate-700 transition"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Payload'}</span>
                </button>
              )}
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400/90 overflow-x-auto whitespace-pre-wrap max-h-48">
              {event.raw_payload || 'No raw payload content recorded for this connection event.'}
            </pre>
          </div>

          {/* Metadata JSON */}
          {event.metadata_json && (
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 font-bold mb-2 flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-slate-400" />
                <span>Parsed Metadata Attributes</span>
              </h4>
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto max-h-36">
                {JSON.stringify(metadataObj, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/60 flex justify-between items-center text-xs text-slate-400 font-mono">
          <span>Timestamp: {new Date(event.timestamp).toUTCString()}</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
