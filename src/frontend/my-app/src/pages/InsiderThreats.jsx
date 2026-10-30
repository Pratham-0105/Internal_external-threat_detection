import React, { useState, useEffect } from 'react';
import { UserCheck, Play, Cpu, CheckCircle2, RefreshCw, Key } from 'lucide-react';
import { insiderService } from '../services/insiderService';
import { StatusPill } from '../components/common/StatusPill';
import { LoadingState } from '../components/common/LoadingState';
import { ErrorState } from '../components/common/ErrorState';

export const InsiderThreats = () => {
  const [engineTest, setEngineTest] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Simulation Form State
  const [simUser, setSimUser] = useState('USR-CORP-01');
  const [simType, setSimType] = useState('DEVICE');
  const [simDetail, setSimDetail] = useState('{"pc":"PC-ENG-04","activity":"Connect","file_tree":"D:\\\\Confidential"}');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const fetchBackendData = async () => {
    try {
      setLoading(true);
      setError(null);
      const testRes = await insiderService.testApi();
      setEngineTest(testRes);
    } catch (err) {
      console.error('Insider engine fetch error:', err);
      setError('Unable to communicate with Insider Threat Engine on Port 5001.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBackendData();
  }, []);

  const handleSimulate = async (e) => {
    e.preventDefault();
    setSimulating(true);
    setSimResult(null);

    try {
      const payload = {
        user: simUser,
        event_type: simType,
        activity: simType === 'DEVICE' ? 'Connect' : simType === 'LOGON' ? 'Logon' : 'Access',
        timestamp: new Date().toISOString(),
        details: simDetail
      };

      const res = await insiderService.ingestEvent(payload);
      setSimResult(res);
    } catch (err) {
      setSimResult({
        status: 'error',
        message: err.response?.data?.message || err.message || 'Simulation request failed'
      });
    } finally {
      setSimulating(false);
    }
  };

  if (loading && !engineTest) {
    return <LoadingState message="Connecting to Insider Threat UEBA Engine (Port 5001)..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-purple-400" />
            Insider Threat Detection & UEBA Ingest Engine
          </h2>
          <div className="text-xs text-gray-400 mt-1 font-mono">
            Trained against CERT r4.2 corporate activity dataset &bull; Dual-stage Keyword Scanner & Isolation Forest
          </div>
        </div>

        <button
          onClick={fetchBackendData}
          className="p-2 text-gray-400 hover:text-white bg-white/5 border border-white/5 rounded-lg self-start sm:self-auto"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && <ErrorState message={error} onRetry={fetchBackendData} />}

      {/* Engine Status & Thresholds */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Detection Engine</span>
          <div className="text-base font-bold text-emerald-400 mt-1 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            {engineTest?.message || 'Active & Responsive'}
          </div>
          <div className="text-gray-400 text-[11px] mt-1">
            Keywords: {engineTest?.keywords_count || 42} Active Signatures
          </div>
        </div>

        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">ML Model</span>
          <div className="text-base font-bold text-purple-400 mt-1 flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            Isolation Forest
          </div>
          <div className="text-gray-400 text-[11px] mt-1">
            Contamination: 0.10 &bull; Random State: 42
          </div>
        </div>

        <div className="soc-panel p-4">
          <span className="text-[10px] font-bold text-gray-400 uppercase">Ingest Authentication</span>
          <div className="text-base font-bold text-cyan-400 mt-1 flex items-center gap-2">
            <Key className="w-4 h-4" />
            X-API-Key Protected
          </div>
          <div className="text-gray-400 text-[11px] mt-1">
            Endpoints: /api/ingest &bull; /api/receive-log
          </div>
        </div>
      </div>

      {/* Live Event Simulator & Real Detection Trigger */}
      <div className="soc-panel p-5">
        <div className="mb-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Play className="w-4 h-4 text-cyan-400" />
            Live Behavioral Event Simulator (Sends to Real Detection Pipeline)
          </h3>
          <p className="text-xs text-gray-400 mt-1">
            Test the real backend detection pipeline by submitting a test user event. It will be scored in real-time by the Isolation Forest model and keyword detector.
          </p>
        </div>

        <form onSubmit={handleSimulate} className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-[11px] font-bold uppercase text-gray-400 mb-1">
              Target User ID
            </label>
            <input
              type="text"
              value={simUser}
              onChange={(e) => setSimUser(e.target.value)}
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase text-gray-400 mb-1">
              Activity Type
            </label>
            <select
              value={simType}
              onChange={(e) => {
                const t = e.target.value;
                setSimType(t);
                if (t === 'DEVICE') setSimDetail('{"pc":"PC-ENG-04","activity":"Connect","file_tree":"D:\\\\Confidential"}');
                else if (t === 'LOGON') setSimDetail('{"pc":"PC-ENG-04","activity":"Logon","time":"02:15:00"}');
                else if (t === 'FILE') setSimDetail('{"pc":"PC-ENG-04","filename":"passwords_dump.txt","content":"secret"}');
                else if (t === 'EMAIL') setSimDetail('{"pc":"PC-ENG-04","to":"competitor@external.com","subject":"financial_exfil"}');
              }}
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500/50"
            >
              <option value="DEVICE">DEVICE (Removable USB Connect)</option>
              <option value="LOGON">LOGON (After-Hours Login)</option>
              <option value="FILE">FILE (Sensitive File Access)</option>
              <option value="EMAIL">EMAIL (External Data Exfiltration)</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase text-gray-400 mb-1">
              Event Details (JSON Payload)
            </label>
            <input
              type="text"
              value={simDetail}
              onChange={(e) => setSimDetail(e.target.value)}
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="sm:col-span-3 flex justify-end">
            <button
              type="submit"
              disabled={simulating}
              className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-purple-600/30 transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {simulating ? 'Processing ML Scoring...' : 'Dispatch Test Event to Ingest API'}
            </button>
          </div>
        </form>

        {/* Real Simulation Response from Ingest API */}
        {simResult && (
          <div className="mt-5 p-4 rounded-lg bg-black/40 border border-white/10 font-mono text-xs space-y-2">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <span className="font-bold text-gray-300">Backend Detection Response:</span>
              <StatusPill
                severity={simResult.risk_level || 'NORMAL'}
                label={simResult.alert_generated ? 'ALERT GENERATED' : 'BENIGN EVENT'}
              />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
              <div>
                <span className="text-gray-400">Event ID:</span> {simResult.event_id}
              </div>
              <div>
                <span className="text-gray-400">Risk Score:</span>{' '}
                <span className="text-rose-400 font-bold">{simResult.risk_score}</span>
              </div>
              <div>
                <span className="text-gray-400">Method:</span> {simResult.detection_method}
              </div>
              <div>
                <span className="text-gray-400">Alert ID:</span> {simResult.alert_id || 'None'}
              </div>
            </div>
            {simResult.description && (
              <div className="text-gray-300 text-[11px] pt-1 border-t border-white/5">
                <span className="text-gray-400">Reason:</span> {simResult.description}
              </div>
            )}
            {simResult.keywords_found?.length > 0 && (
              <div className="text-amber-400 text-[11px]">
                <span className="text-gray-400">Matched Keywords:</span> {simResult.keywords_found.join(', ')}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
