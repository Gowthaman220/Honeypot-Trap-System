import React from 'react';

interface RiskScoreBarProps {
  score: number;
  showText?: boolean;
}

export const RiskScoreBar: React.FC<RiskScoreBarProps> = ({ score, showText = true }) => {
  const normalized = Math.max(0, Math.min(100, score || 0));

  const getColor = () => {
    if (normalized >= 80) return 'bg-red-500 text-red-400';
    if (normalized >= 60) return 'bg-amber-500 text-amber-400';
    if (normalized >= 30) return 'bg-yellow-400 text-yellow-300';
    return 'bg-emerald-500 text-emerald-400';
  };

  return (
    <div className="flex items-center space-x-2">
      <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full transition-all duration-300 ${getColor().split(' ')[0]}`}
          style={{ width: `${normalized}%` }}
        />
      </div>
      {showText && (
        <span className={`text-xs font-mono font-semibold ${getColor().split(' ')[1]}`}>
          {normalized}/100
        </span>
      )}
    </div>
  );
};
