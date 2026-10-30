import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { nidsService } from '../services/nidsService';
import { insiderService } from '../services/insiderService';
import { systemService } from '../services/systemService';
import { socketService } from '../services/socketService';

const SOCContext = createContext(null);

export const SOCProvider = ({ children }) => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [defenseStatus, setDefenseStatus] = useState({
    enabled: true,
    blocked_ips: [],
    blocked_ips_count: 0
  });

  const [systemStatus, setSystemStatus] = useState({
    aiEngine: { online: false, text: 'Connecting...' },
    networkMonitor: { online: false, text: 'Connecting...' },
    mlService: { online: false, text: 'Connecting...' },
    database: { online: false, text: 'Connecting...' }
  });

  const [wsConnected, setWsConnected] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeNotification, setActiveNotification] = useState(null);

  const dismissNotification = useCallback(() => {
    setActiveNotification(null);
  }, []);

  const triggerThreatNotification = useCallback((notif) => {
    setActiveNotification({
      id: Date.now(),
      title: notif.title || 'CRITICAL THREAT INTERCEPTED',
      vector: notif.vector || 'Malicious Exploit',
      target: notif.target || '192.168.1.50',
      action: notif.action || 'IP Blocked & Traffic Quarantined',
      confidence: notif.confidence || 98.5,
      time: new Date().toLocaleTimeString()
    });
  }, []);

  // Fetch real persisted incidents from backend (NIDS + Insider Threat UEBA)
  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [nidsRes, insiderRes] = await Promise.allSettled([
        nidsService.getIncidents(),
        insiderService.getAlerts({ limit: 100 })
      ]);

      let nidsData = [];
      if (nidsRes.status === 'fulfilled' && Array.isArray(nidsRes.value)) {
        nidsData = nidsRes.value;
      }

      let insiderAlerts = [];
      if (insiderRes.status === 'fulfilled' && insiderRes.value?.alerts && Array.isArray(insiderRes.value.alerts)) {
        insiderAlerts = insiderRes.value.alerts.map((alert) => {
          const alertType = alert.alert_type || 'UEBA';
          const alertDesc = alert.description || 'Suspicious user behavior detected';
          const cleanDesc = alertDesc.replace(/^SUSPICIOUS\s+LOGON:\s*|AFTER-HOURS\s+FILE\s+ACCESS:\s*|CRITICAL\s+DATA\s+EXFILTRATION:\s*/i, '');
          return {
            id: `insider_${alert.alert_id || alert.id}`,
            timestamp: alert.timestamp || new Date().toISOString(),
            time_display: alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString(),
            vector: `Insider: ${alertType} (${alertDesc.length > 40 ? alertDesc.slice(0, 40) + '...' : alertDesc})`,
            category: 'Insider Threat',
            src_ip: alert.department ? `Dept: ${alert.department}` : 'Internal Host',
            dst_ip: `${alert.full_name || 'Employee'} (${alert.user_id || 'User'})`,
            username: alert.full_name || alert.user_id,
            user_id: alert.user_id,
            is_attack: true,
            severity: alert.risk_level || 'HIGH',
            confidence: Math.round((alert.risk_score || 0.85) * 100),
            prediction: 1,
            latency: 14.2,
            status: alert.status === 'RESOLVED' ? 'RESOLVED' : 'NEW',
            action_taken: alert.risk_level === 'CRITICAL' ? 'Account Quarantined & Session Terminated' : 'Behavior Flagged & Access Monitored',
            notes: alertDesc,
            rawAlert: alert
          };
        });
      }

      const normalizedNids = nidsData.map((inc) => {
        const vec = (inc.vector || '').toLowerCase();
        const dst = (inc.dst_ip || '').toLowerCase();
        const isInsider = inc.category === 'Insider Threat' || vec.includes('insider') || dst.includes('usr-') || dst.includes('dev.engineer') || dst.includes('internal.analyst');
        return {
          ...inc,
          category: isInsider ? 'Insider Threat' : (inc.category || (inc.is_attack ? 'External Threat' : 'Normal Traffic')),
          severity: inc.severity || (inc.is_attack ? (inc.confidence > 90 ? 'CRITICAL' : 'HIGH') : 'LOW')
        };
      });

      const combined = [...normalizedNids, ...insiderAlerts];
      combined.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
      setIncidents(combined);
    } catch (err) {
      console.error('Failed to fetch incidents:', err);
      setError('Unable to connect to CASOC backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch defense status
  const fetchDefenseStatus = useCallback(async () => {
    try {
      const data = await nidsService.getDefenseStatus();
      if (data) {
        setDefenseStatus(data);
      }
    } catch (err) {
      console.warn('Defense status fetch failed:', err);
    }
  }, []);

  // Fetch system component statuses
  const fetchSystemStatus = useCallback(async () => {
    try {
      const data = await systemService.getSystemStatus();
      setSystemStatus(data);
    } catch (err) {
      console.warn('System status fetch failed:', err);
    }
  }, []);

  // Initial load & WebSocket setup
  useEffect(() => {
    fetchIncidents();
    fetchDefenseStatus();
    fetchSystemStatus();

    // Connect Socket.IO
    socketService.connect();

    const unsubWs = socketService.subscribe('connection_change', (connected) => {
      setWsConnected(connected);
    });

    const unsubThreat = socketService.subscribe('new_threat_event', (eventData) => {
      const vec = (eventData.category || eventData.vector || '').toLowerCase();
      const dst = (eventData.dst_ip || '').toLowerCase();
      const isInsider = vec.includes('insider') || dst.includes('usr-') || dst.includes('dev.engineer') || dst.includes('internal.analyst') || Boolean(eventData.user_id);

      const newInc = {
        id: eventData.id || Date.now(),
        timestamp: new Date().toISOString(),
        time_display: new Date().toLocaleTimeString(),
        vector: eventData.vector || eventData.category || 'Security Threat',
        category: isInsider ? 'Insider Threat' : (eventData.is_attack ? 'External Threat' : 'Normal Traffic'),
        src_ip: eventData.src_ip || 'Internal Network',
        dst_ip: eventData.dst_ip,
        username: eventData.username,
        user_id: eventData.user_id,
        is_attack: Boolean(eventData.is_attack),
        severity: eventData.threat_severity || (eventData.is_attack ? 'CRITICAL' : 'LOW'),
        confidence: eventData.confidence || 0,
        prediction: eventData.prediction || 0,
        latency: eventData.latency || 0,
        status: eventData.is_attack ? 'NEW' : 'RESOLVED',
        action_taken: eventData.action_taken || 'Logged',
        notes: '',
        rawEvent: eventData
      };

      setIncidents((prev) => [newInc, ...prev.slice(0, 149)]);
      fetchDefenseStatus();

      // Trigger high-visibility on-screen notification
      if (eventData.is_attack) {
        setActiveNotification({
          id: Date.now(),
          title: '🚨 LIVE ATTACK INTERCEPTED BY CASOC',
          vector: eventData.category || 'Security Threat',
          target: eventData.dst_ip || 'Internal Host',
          action: eventData.action_taken || 'Firewall Mitigation Active',
          confidence: eventData.confidence || 98.2,
          time: new Date().toLocaleTimeString()
        });
      }
    });

    const unsubClear = socketService.subscribe('incidents_cleared', () => {
      setIncidents([]);
    });

    // Poll system health every 15 seconds
    const interval = setInterval(() => {
      fetchSystemStatus();
    }, 15000);

    return () => {
      unsubWs();
      unsubThreat();
      unsubClear();
      clearInterval(interval);
    };
  }, [fetchIncidents, fetchDefenseStatus, fetchSystemStatus]);

  // Derived KPI calculations based strictly on real backend data
  const kpis = {
    totalEvents: incidents.length,
    activeThreats: incidents.filter((i) => i.is_attack && (i.status === 'NEW' || i.status === 'INVESTIGATING')).length,
    maliciousEvents: incidents.filter((i) => i.is_attack).length,
    blockedIpsCount: defenseStatus.blocked_ips_count || defenseStatus.blocked_ips?.length || 0,
    overallRiskScore: incidents.length === 0 ? 0 : Math.round(
      Math.min(
        100,
        (incidents.filter((i) => i.is_attack).length / (incidents.length || 1)) * 70 +
        (incidents.some((i) => i.confidence > 90) ? 25 : 5)
      )
    )
  };

  const metrics = {
    ...kpis,
    threatsNeutralized: incidents.length === 0 ? 100 : Math.round(
      (incidents.filter((i) => !i.is_attack || i.status === 'RESOLVED').length / incidents.length) * 100
    )
  };

  const handleTriage = async (id, newStatus, notes) => {
    try {
      await nidsService.triageIncident(id, newStatus, notes);
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === id ? { ...inc, status: newStatus, notes } : inc))
      );
      if (selectedIncident && selectedIncident.id === id) {
        setSelectedIncident((prev) => ({ ...prev, status: newStatus, notes }));
      }
      return true;
    } catch (e) {
      console.error('Triage update failed:', e);
      return false;
    }
  };

  const clearAllIncidents = useCallback(async () => {
    try {
      setLoading(true);
      await nidsService.clearIncidents();
      setIncidents([]);
      return true;
    } catch (err) {
      console.error('Failed to clear incidents:', err);
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <SOCContext.Provider
      value={{
        incidents,
        loading,
        error,
        kpis,
        metrics,
        defenseStatus,
        systemStatus,
        wsConnected,
        selectedIncident,
        setSelectedIncident,
        activeNotification,
        dismissNotification,
        triggerThreatNotification,
        fetchIncidents,
        refreshAll: fetchIncidents,
        clearAllIncidents,
        fetchDefenseStatus,
        fetchSystemStatus,
        handleTriage
      }}
    >
      {children}
    </SOCContext.Provider>
  );
};

export const useSOC = () => {
  const context = useContext(SOCContext);
  if (!context) {
    throw new Error('useSOC must be used within a SOCProvider');
  }
  return context;
};
