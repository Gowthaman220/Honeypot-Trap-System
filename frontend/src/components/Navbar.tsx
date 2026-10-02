import React from 'react';
import { Shield, Radio, LogOut, Terminal, Activity } from 'lucide-react';
import { api } from '../services/api';

interface NavbarProps {
  wsConnected: boolean;
  username: string;
}

export const Navbar: React.FC<NavbarProps> = ({ wsConnected, username }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0d1322] px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3">
        <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-base font-bold text-white tracking-wide uppercase font-mono">
              Honeypot Trap System
            </h1>
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
              SOC v1.0
            </span>
          </div>
          <p className="text-xs text-slate-400">Defensive Cybersecurity Threat Intelligence Engine</p>
        </div>
      </div>

      <div className="flex items-center space-x-6">
        {/* Real-time telemetry pulse */}
        <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-full border border-slate-800 bg-slate-900/80">
          <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
          <span className={wsConnected ? 'text-emerald-400' : 'text-amber-400'}>
            {wsConnected ? 'LIVE FEED CONNECTED' : 'POLLING FALLBACK'}
          </span>
        </div>

        {/* User profile */}
        <div className="flex items-center space-x-3 pl-4 border-l border-slate-800">
          <div className="text-right">
            <p className="text-xs font-semibold text-slate-200">{username || 'Admin'}</p>
            <span className="text-[10px] text-slate-400 font-mono">SEC_OPERATOR</span>
          </div>
          <button
            onClick={() => api.logout()}
            title="Log Out"
            className="p-2 rounded-lg hover:bg-red-500/10 hover:text-red-400 text-slate-400 border border-slate-800 transition"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
