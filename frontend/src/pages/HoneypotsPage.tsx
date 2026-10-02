import React, { useState, useEffect } from 'react';
import { Server, Play, Square, RefreshCw, ShieldCheck, Activity, Terminal, Globe, HardDrive } from 'lucide-react';
import { api } from '../services/api';
import { HoneypotServiceItem } from '../types';

export const HoneypotsPage: React.FC = () => {
  const [services, setServices] = useState<HoneypotServiceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const fetchServices = async () => {
    setLoading(true);
    try {
      const data = await api.getHoneypotServices();
      setServices(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, []);

  const handleToggleService = async (service: HoneypotServiceItem) => {
    setActionLoading(service.id);
    setMessage(null);
    try {
      if (service.status === 'running') {
        await api.stopService(service.id);
        setMessage(`Honeypot service ${service.name} stopped successfully.`);
      } else {
        await api.startService(service.id);
        setMessage(`Honeypot service ${service.name} started successfully.`);
      }
      await fetchServices();
    } catch (err: any) {
      setMessage(`Error: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const getServiceIcon = (type: string) => {
    switch (type.toUpperCase()) {
      case 'SSH':
        return <Terminal className="w-6 h-6 text-sky-400" />;
      case 'HTTP':
        return <Globe className="w-6 h-6 text-emerald-400" />;
      case 'FTP':
        return <HardDrive className="w-6 h-6 text-amber-400" />;
      default:
        return <Server className="w-6 h-6 text-indigo-400" />;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide font-mono uppercase">
            Honeypot Services & Decoy Listeners
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Controlled simulated services with isolated socket handlers and zero-compromise emulation
          </p>
        </div>
        <button
          onClick={fetchServices}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-xs font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {message && (
        <div className="p-3 bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-mono rounded-lg flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 flex-shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {services.map((svc) => {
          const isRunning = svc.status === 'running';
          return (
            <div
              key={svc.id}
              className="p-5 bg-[#111827] border border-slate-800 rounded-xl space-y-4 shadow-xl flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      {getServiceIcon(svc.service_type)}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="text-base font-bold text-white font-mono">{svc.name}</h3>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider ${
                            isRunning
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                              isRunning ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                            }`}
                          />
                          {svc.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{svc.description}</p>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 mt-5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase">Listening Port</span>
                    <p className="text-sm font-bold text-slate-200">{svc.port}/{svc.protocol}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase">Total Ingested</span>
                    <p className="text-sm font-bold text-sky-400">{svc.event_count} events</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase">Last Activity</span>
                    <p className="text-[11px] text-slate-300">
                      {svc.last_activity ? new Date(svc.last_activity).toLocaleTimeString() : 'Idle'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Action Controls */}
              <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-500 font-mono">
                  Socket binding: 0.0.0.0:{svc.port}
                </span>
                <button
                  onClick={() => handleToggleService(svc)}
                  disabled={actionLoading === svc.id}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition disabled:opacity-50 ${
                    isRunning
                      ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40'
                      : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/40'
                  }`}
                >
                  {isRunning ? (
                    <>
                      <Square className="w-3.5 h-3.5 fill-current" />
                      <span>Stop Listener</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Start Listener</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Safety Notice Card */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-400 space-y-1 font-mono">
        <div className="flex items-center space-x-2 text-slate-200 font-bold">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Academic Safety Architecture & Containment Guarantee</span>
        </div>
        <p className="text-slate-400 leading-relaxed">
          All honeypot listeners operate as controlled mock protocol daemons. No real system shells, underlying filesystems, or production databases are connected. Credentials and payloads are safely recorded into sandbox telemetry.
        </p>
      </div>
    </div>
  );
};
