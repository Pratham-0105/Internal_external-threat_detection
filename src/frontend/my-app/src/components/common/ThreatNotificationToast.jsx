import React, { useEffect } from 'react';
import { ShieldAlert, X, ExternalLink, Zap } from 'lucide-react';
import { useSOC } from '../../context/SOCContext';
import { useNavigate } from 'react-router-dom';

export const ThreatNotificationToast = () => {
  const { activeNotification, dismissNotification } = useSOC();
  const navigate = useNavigate();

  useEffect(() => {
    if (activeNotification) {
      const timer = setTimeout(() => {
        dismissNotification();
      }, 8000);
      return () => clearTimeout(timer);
    }
  }, [activeNotification, dismissNotification]);

  if (!activeNotification) return null;

  return (
    <div className="fixed top-5 right-6 z-50 max-w-md w-full animate-bounce-in select-none">
      <div className="bg-[#0f172a] border-2 border-rose-500/80 rounded-xl p-4 shadow-2xl shadow-rose-950/80 relative overflow-hidden ring-4 ring-rose-500/20">
        {/* Glowing cyber pulse bar */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-red-500 to-amber-500 animate-pulse" />

        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shrink-0 mt-0.5">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase font-black tracking-wider px-1.5 py-0.5 rounded bg-rose-500 text-black">
                  ACTIVE ALERT
                </span>
                <span className="text-xs font-bold text-white tracking-wide">
                  {activeNotification.title}
                </span>
              </div>

              <div className="text-xs font-bold text-rose-300">
                {activeNotification.vector}
              </div>

              <div className="text-[11px] font-mono text-gray-300">
                Target: <span className="text-white font-bold">{activeNotification.target}</span>
              </div>

              <div className="text-[11px] font-mono text-emerald-400 font-semibold flex items-center gap-1">
                <Zap className="w-3 h-3 text-amber-400" />
                {activeNotification.action}
              </div>
            </div>
          </div>

          <button
            onClick={dismissNotification}
            className="text-gray-400 hover:text-white p-1 rounded hover:bg-white/10 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Footer Jump Button */}
        <div className="mt-3 pt-2.5 border-t border-white/10 flex items-center justify-between text-xs font-mono">
          <span className="text-[10px] text-gray-400">
            CONFIDENCE: {Math.round(activeNotification.confidence)}% | {activeNotification.time}
          </span>
          <button
            onClick={() => {
              dismissNotification();
              navigate('/admin-workspace');
            }}
            className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 hover:text-white border border-rose-500/40 flex items-center gap-1 font-bold transition-all"
          >
            <span>View in Admin Vault</span>
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
};
