import React from 'react';
import { FileText, Download, Clock } from 'lucide-react';
import { useSOC } from '../context/SOCContext';

export const Reports = () => {
  const { incidents } = useSOC();

  const handleExportCSV = () => {
    if (!incidents || incidents.length === 0) return;
    let csv = "ID,Timestamp,Time,Vector,Source_IP,Destination_IP,Is_Attack,Confidence,Latency_MS,Status,Action_Taken,Notes\n";
    incidents.forEach((inc) => {
      csv += `"${inc.id}","${inc.timestamp}","${inc.time_display}","${inc.vector}","${inc.src_ip}","${inc.dst_ip}","${inc.is_attack}","${inc.confidence}","${inc.latency}","${inc.status}","${inc.action_taken || 'None'}","${(inc.notes || '').replace(/"/g, '""')}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `CASOC_Forensic_Incident_Report_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const reportCards = [
    {
      title: 'Real-time Forensic CSV Incident Export',
      desc: 'Complete tabular export of all SQLite persisted incident records, confidence ratings, and analyst notes.',
      date: 'Generated on-demand from live DB',
      records: `${incidents.length} Records Available`,
      actionText: 'Export Forensic CSV',
      onDownload: handleExportCSV
    },
    {
      title: 'Daily Operational Threat Summary',
      desc: '24-hour breakdown of inbound flow volume, DDoS surges, and anomalous employee logons.',
      date: 'Daily Automated Audit',
      records: `${incidents.filter((i) => i.is_attack).length} Attacks Logged`,
      actionText: 'Export Daily Log',
      onDownload: handleExportCSV
    },
    {
      title: 'UEBA Insider Risk Assessment Report',
      desc: 'Behavioral deviation report compiling USB connects, after-hours logons, and DLP file flags.',
      date: 'Weekly Compliance Audit',
      records: 'CERT r4.2 Persona Analysis',
      actionText: 'Export UEBA Summary',
      onDownload: handleExportCSV
    },
    {
      title: 'SOC Executive KPI Overview',
      desc: 'High-level executive metrics detailing containment rates, firewall bans, and model accuracy.',
      date: 'Monthly Executive Briefing',
      records: 'Executive Metrics Ready',
      actionText: 'Export KPI Report',
      onDownload: handleExportCSV
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="soc-panel p-5">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          Security Operations Center Reports & Forensic Exports
        </h2>
        <div className="text-xs text-gray-400 mt-1 font-mono">
          Export full forensic audit trails directly from the SQLite incident persistence engine
        </div>
      </div>

      {/* Reports Grid per Section 24 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {reportCards.map((rep) => (
          <div key={rep.title} className="soc-panel p-5 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                  {rep.title}
                </h3>
                <span className="text-[10px] font-mono text-cyan-400 font-semibold bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  {rep.records}
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-2 leading-relaxed">{rep.desc}</p>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-gray-400 mt-3">
                <Clock className="w-3.5 h-3.5" />
                {rep.date}
              </div>
            </div>

            <button
              onClick={rep.onDownload}
              className="w-full py-2 bg-white/5 hover:bg-cyan-500/20 text-gray-200 hover:text-cyan-300 border border-white/10 hover:border-cyan-500/40 rounded-lg text-xs font-bold font-mono uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              {rep.actionText}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
