import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Sliders, Clock, Cpu, Save, CheckCircle2, AlertCircle } from 'lucide-react';
import { insiderService } from '../services/insiderService';
import { LoadingState } from '../components/common/LoadingState';

export const Settings = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedMessage, setSavedMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  // Controlled form state
  const [keywordEnabled, setKeywordEnabled] = useState(true);
  const [mlEnabled, setMlEnabled] = useState(true);
  const [keywordsCount, setKeywordsCount] = useState(42);
  const [critical, setCritical] = useState(0.9);
  const [high, setHigh] = useState(0.7);
  const [medium, setMedium] = useState(0.4);
  const [low, setLow] = useState(0.2);
  const [startHour, setStartHour] = useState(8);
  const [endHour, setEndHour] = useState(18);

  useEffect(() => {
    insiderService
      .getSettings()
      .then((res) => {
        if (res && res.settings) {
          const s = res.settings;
          setKeywordEnabled(s.keyword_detection_enabled ?? true);
          setMlEnabled(s.ml_detection_enabled ?? true);
          setKeywordsCount(s.keywords_count || 42);
          if (s.thresholds) {
            setCritical(s.thresholds.critical ?? 0.9);
            setHigh(s.thresholds.high ?? 0.7);
            setMedium(s.thresholds.medium ?? 0.4);
            setLow(s.thresholds.low ?? 0.2);
          }
          if (s.business_hours) {
            setStartHour(s.business_hours.start ?? 8);
            setEndHour(s.business_hours.end ?? 18);
          }
        }
      })
      .catch((e) => console.warn('Settings load error:', e))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSavedMessage('');
    setErrorMessage('');

    try {
      const payload = {
        keyword_detection_enabled: keywordEnabled,
        ml_detection_enabled: mlEnabled,
        thresholds: {
          critical: parseFloat(critical),
          high: parseFloat(high),
          medium: parseFloat(medium),
          low: parseFloat(low)
        },
        business_hours: {
          start: parseInt(startHour, 10),
          end: parseInt(endHour, 10)
        }
      };

      const res = await insiderService.updateSettings(payload);
      setSavedMessage(res.message || 'Settings persisted to backend instance successfully!');
      setTimeout(() => setSavedMessage(''), 5000);
    } catch (err) {
      setErrorMessage(err.response?.data?.message || 'Failed to update settings in backend');
      setTimeout(() => setErrorMessage(''), 5000);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <LoadingState message="Loading SOC detection settings & parameters..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <SettingsIcon className="w-4 h-4 text-cyan-400" />
          CASOC System Thresholds & Detection Configuration
        </h2>
        <div className="text-xs text-gray-400 mt-1 font-mono">
          Dynamic threat scoring boundaries, business hour policies, and dual-layer ML parameters
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Detection Engine Switches */}
        <div className="soc-panel p-5 space-y-4">
          <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" />
            Detection Subsystem Toggles
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
            <div className="p-4 rounded-lg bg-black/30 border border-white/5 flex items-center justify-between">
              <div>
                <span className="font-bold text-gray-200">Keyword Fast-Path Scanner</span>
                <p className="text-gray-400 text-[11px] mt-0.5">Scans outbound emails and files ({keywordsCount} patterns)</p>
              </div>
              <button
                type="button"
                onClick={() => setKeywordEnabled(!keywordEnabled)}
                className={`font-bold px-3 py-1 rounded transition-colors ${
                  keywordEnabled
                    ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20'
                    : 'text-gray-400 bg-gray-500/10 border border-gray-500/20'
                }`}
              >
                {keywordEnabled ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            <div className="p-4 rounded-lg bg-black/30 border border-white/5 flex items-center justify-between">
              <div>
                <span className="font-bold text-gray-200">Isolation Forest UEBA</span>
                <p className="text-gray-400 text-[11px] mt-0.5">Unsupervised behavioral anomaly scoring</p>
              </div>
              <button
                type="button"
                onClick={() => setMlEnabled(!mlEnabled)}
                className={`font-bold px-3 py-1 rounded transition-colors ${
                  mlEnabled
                    ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20'
                    : 'text-gray-400 bg-gray-500/10 border border-gray-500/20'
                }`}
              >
                {mlEnabled ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>
          </div>
        </div>

        {/* Threat Scoring Thresholds */}
        <div className="soc-panel p-5 space-y-4">
          <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            Risk Classification Thresholds (0.00 &mdash; 1.00)
          </h3>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div>
              <label className="block text-[10px] uppercase font-bold text-rose-400 mb-1">CRITICAL</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                value={critical}
                onChange={(e) => setCritical(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-[10px] uppercase font-bold text-orange-400 mb-1">HIGH</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                value={high}
                onChange={(e) => setHigh(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-[10px] uppercase font-bold text-amber-400 mb-1">MEDIUM</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                value={medium}
                onChange={(e) => setMedium(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-[10px] uppercase font-bold text-emerald-400 mb-1">LOW</label>
              <input
                type="number"
                step="0.05"
                min="0.0"
                max="1.0"
                value={low}
                onChange={(e) => setLow(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
          </div>
        </div>

        {/* Business Hours & Policy */}
        <div className="soc-panel p-5 space-y-4">
          <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400" />
            Corporate Business Hours & Weekend Policy
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
            <div>
              <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1">
                Day Shift Start Hour (24H)
              </label>
              <input
                type="number"
                min="0"
                max="23"
                value={startHour}
                onChange={(e) => setStartHour(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-[10px] uppercase font-bold text-gray-400 mb-1">
                Day Shift End Hour (24H)
              </label>
              <input
                type="number"
                min="0"
                max="23"
                value={endHour}
                onChange={(e) => setEndHour(e.target.value)}
                className="w-full bg-[#131c2e] border border-white/10 rounded px-3 py-2 text-white"
              />
            </div>
          </div>
        </div>

        {/* Status Alerts & Save Button */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            {savedMessage && (
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                {savedMessage}
              </span>
            )}
            {errorMessage && (
              <span className="text-xs font-mono text-rose-400 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4" />
                {errorMessage}
              </span>
            )}
          </div>
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold uppercase font-mono tracking-wider flex items-center gap-2 shadow-lg shadow-cyan-600/30 transition-all disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Apply Changes'}
          </button>
        </div>
      </form>
    </div>
  );
};
