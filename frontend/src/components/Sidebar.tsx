import React from 'react';
import {
  LayoutDashboard,
  Radio,
  FileSearch,
  Server,
  Bell,
  FileText,
  Settings,
  ShieldAlert
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  newAlertsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, newAlertsCount }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'live_events', label: 'Live Events', icon: Radio },
    { id: 'threat_analysis', label: 'Threat Analysis', icon: FileSearch },
    { id: 'honeypots', label: 'Honeypot Services', icon: Server },
    { id: 'alerts', label: 'Alerts', icon: Bell, count: newAlertsCount },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0d1322] flex flex-col justify-between p-4 min-h-[calc(100vh-4rem)]">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono font-semibold uppercase text-slate-500 tracking-wider">
          Security Operations
        </div>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.count !== undefined && item.count > 0 && (
                <span className="px-1.5 py-0.5 text-xs font-mono font-bold rounded-full bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-900/40 text-xs text-slate-400">
        <div className="flex items-center space-x-2 text-slate-300 font-medium mb-1">
          <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
          <span>Defensive Containment</span>
        </div>
        <p className="text-[11px] text-slate-500 leading-relaxed">
          Simulated honeypot decoys active. External exploitation safely neutralized.
        </p>
      </div>
    </aside>
  );
};
