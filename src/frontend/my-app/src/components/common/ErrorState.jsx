import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export const ErrorState = ({
  title = "BACKEND CONNECTION ERROR",
  message = "Unable to connect to CASOC backend services. Please verify that the Flask API (Port 5005) and Insider Threat services (Port 5001) are active.",
  onRetry
}) => {
  return (
    <div className="soc-panel p-8 text-center border-rose-500/30 bg-rose-950/10 my-6">
      <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 mx-auto mb-3">
        <AlertTriangle className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-bold tracking-wider text-rose-400 uppercase">{title}</h3>
      <p className="mt-2 text-xs text-gray-300 max-w-lg mx-auto leading-relaxed">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-rose-300 bg-rose-900/30 border border-rose-700/50 rounded-lg hover:bg-rose-900/50 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          RETRY
        </button>
      )}
    </div>
  );
};
