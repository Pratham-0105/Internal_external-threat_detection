import React from 'react';

export const MetricCard = ({ title, value, subtitle, icon: Icon, trend, trendType = 'neutral', color = 'cyan' }) => {
  const colorMap = {
    cyan: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/5',
    rose: 'text-rose-400 border-rose-500/20 bg-rose-500/5',
    amber: 'text-amber-400 border-amber-500/20 bg-amber-500/5',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5',
    blue: 'text-blue-400 border-blue-500/20 bg-blue-500/5',
    violet: 'text-purple-400 border-purple-500/20 bg-purple-500/5',
  };

  const selectedTheme = colorMap[color] || colorMap.cyan;

  return (
    <div className="soc-panel soc-panel-hover p-4 relative overflow-hidden flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs font-semibold text-gray-400 tracking-wider uppercase">{title}</span>
          <div className="mt-2 text-2xl font-bold tracking-tight text-white font-mono">{value}</div>
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-lg border ${selectedTheme}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-center justify-between text-xs text-gray-400 border-t border-white/5 pt-2">
        <span>{subtitle}</span>
        {trend && (
          <span className={trendType === 'danger' ? 'text-rose-400 font-medium' : trendType === 'success' ? 'text-emerald-400 font-medium' : 'text-gray-400'}>
            {trend}
          </span>
        )}
      </div>
    </div>
  );
};
