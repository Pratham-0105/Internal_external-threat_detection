import React from 'react';
import { Dna } from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';

export const ThreatDNA = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="soc-panel p-5">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Dna className="w-4 h-4 text-purple-400" />
          Threat DNA & Behavioral Fingerprints
        </h2>
        <div className="text-xs text-gray-400 mt-1 font-mono">
          High-dimensional behavioral clustering mapping multi-vector attributes into distinct attack DNA signatures
        </div>
      </div>

      {/* Six Threat DNA Dimensions per Section 17 */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono text-xs">
        {[
          { name: 'Network Pattern', desc: 'Flow duration & IAT' },
          { name: 'Login Pattern', desc: 'Logon hours & DC auth' },
          { name: 'File Behaviour', desc: 'Access volume & extent' },
          { name: 'Privilege Usage', desc: 'Admin & sudo tokens' },
          { name: 'Data Transfer', desc: 'Payload exfil bytes' },
          { name: 'Attack Pattern', desc: 'Known MITRE vectors' }
        ].map((dim) => (
          <div key={dim.name} className="soc-panel p-3 text-center border-white/5 bg-white/[0.01]">
            <span className="text-[10px] uppercase font-bold text-gray-400">{dim.name}</span>
            <div className="mt-1 text-xs text-gray-400">{dim.desc}</div>
          </div>
        ))}
      </div>

      {/* Explicit Empty State strictly following Section 17 & Rule 3 */}
      <EmptyState
        icon={Dna}
        title="Threat DNA engine awaiting cluster activation"
        description="Threat DNA data will appear when the CASOC Threat DNA engine is connected."
      />
    </div>
  );
};
