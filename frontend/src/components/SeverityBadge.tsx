import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const sev = (severity || 'LOW').toUpperCase();

  const getStyles = () => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border border-red-500/50 animate-pulse';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
      case 'LOW':
      default:
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    }
  };

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : size === 'md' ? 'px-2.5 py-1 text-sm' : 'px-3 py-1.5 text-base';

  return (
    <span className={`inline-flex items-center font-medium rounded-full uppercase tracking-wider font-mono ${sizeClasses} ${getStyles()}`}>
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
        sev === 'CRITICAL' ? 'bg-red-400' : sev === 'HIGH' ? 'bg-amber-400' : sev === 'MEDIUM' ? 'bg-yellow-400' : 'bg-emerald-400'
      }`} />
      {sev}
    </span>
  );
};
