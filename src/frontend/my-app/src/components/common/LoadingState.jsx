import React from 'react';
import { Loader2 } from 'lucide-react';

export const LoadingState = ({ message = "Loading security events..." }) => {
  return (
    <div className="soc-panel p-12 text-center flex flex-col items-center justify-center my-6">
      <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mb-3" />
      <span className="text-xs font-medium tracking-wide text-gray-300 uppercase font-mono">{message}</span>
    </div>
  );
};
