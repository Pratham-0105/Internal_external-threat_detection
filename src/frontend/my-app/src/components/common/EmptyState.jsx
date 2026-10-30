import React from 'react';
import { ShieldCheck } from 'lucide-react';

export const EmptyState = ({
  title = "No security events available",
  description = "No items matched your current filter criteria or the backend hasn't recorded telemetry yet.",
  icon: Icon = ShieldCheck,
  actionText,
  onAction
}) => {
  return (
    <div className="soc-panel p-12 text-center flex flex-col items-center justify-center my-6 border-dashed border-gray-800">
      <div className="w-14 h-14 rounded-full bg-gray-900/80 border border-gray-800 flex items-center justify-center text-gray-400 mb-4 shadow-inner">
        <Icon className="w-7 h-7 text-cyan-500/80" />
      </div>
      <h3 className="text-base font-semibold text-gray-200">{title}</h3>
      <p className="mt-1 text-sm text-gray-400 max-w-md">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="mt-5 inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 rounded-lg hover:bg-cyan-900/40 transition-colors"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
