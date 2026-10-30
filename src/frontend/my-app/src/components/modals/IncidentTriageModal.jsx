import React, { useState } from 'react';
import { X, CheckCircle2 } from 'lucide-react';
import { useSOC } from '../../context/SOCContext';

export const IncidentTriageModal = ({ incident, onClose }) => {
  const { handleTriage } = useSOC();
  const [status, setStatus] = useState(incident?.status || 'INVESTIGATING');
  const [notes, setNotes] = useState(incident?.notes || '');
  const [saving, setSaving] = useState(false);

  if (!incident) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    const success = await handleTriage(incident.id, status, notes);
    setSaving(false);
    if (success) {
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="soc-panel w-full max-w-md border border-white/10 shadow-2xl bg-[#0f1523]">
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono">
              Incident Triage &mdash; #{incident.id}
            </h3>
            <p className="text-[11px] text-gray-400 font-mono">{incident.vector}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-white/5"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-bold uppercase text-gray-400 mb-1.5">
              Incident Status
            </label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500/50 font-mono"
            >
              <option value="NEW">NEW (Unreviewed)</option>
              <option value="INVESTIGATING">INVESTIGATING (Under Analysis)</option>
              <option value="RESOLVED">RESOLVED (Threat Mitigated)</option>
              <option value="FALSE_POSITIVE">FALSE_POSITIVE (Benign / Whitelisted)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-bold uppercase text-gray-400 mb-1.5">
              Analyst Resolution Notes
            </label>
            <textarea
              rows={4}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Enter forensic observations, IP block validation, or root-cause details..."
              className="w-full bg-[#131c2e] border border-white/10 rounded-lg p-3 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 resize-none font-sans"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-white/5">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs font-medium text-gray-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg flex items-center gap-1.5 shadow-md shadow-cyan-600/30"
            >
              {saving ? 'Saving...' : (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Save Triage Record
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
