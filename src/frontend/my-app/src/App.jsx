import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SOCProvider } from './context/SOCContext';
import { AuthProvider } from './context/AuthContext';
import { Layout } from './components/layout/Layout';

// Pages
import { Dashboard } from './pages/Dashboard';
import { NetworkMonitor } from './pages/NetworkMonitor';
import { AttackDetection } from './pages/AttackDetection';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { UserBehaviour } from './pages/UserBehaviour';
import { InsiderThreats } from './pages/InsiderThreats';
import { UserInvestigation } from './pages/UserInvestigation';
import { ThreatCorrelation } from './pages/ThreatCorrelation';
import { ThreatDNA } from './pages/ThreatDNA';
import { ThreatMemory } from './pages/ThreatMemory';
import { BehaviourEvolution } from './pages/BehaviourEvolution';
import { ExplainableAI } from './pages/ExplainableAI';
import { Incidents } from './pages/Incidents';
import { AutomatedResponse } from './pages/AutomatedResponse';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { AttackSimulator } from './pages/AttackSimulator';
import { ScenarioRunner } from './pages/ScenarioRunner';
import { FacultyDemoMode } from './pages/FacultyDemoMode';
import { AdminWorkspace } from './pages/AdminWorkspace';
import { UserWorkspace } from './pages/UserWorkspace';
import { AttackerWorkspace } from './pages/AttackerWorkspace';
import { MitreMatrix } from './pages/MitreMatrix';
import { AICopilot } from './pages/AICopilot';
import { GlobalThreatRadar } from './pages/GlobalThreatRadar';

function App() {
  return (
    <AuthProvider>
      <SOCProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="admin-workspace" element={<AdminWorkspace />} />
              <Route path="user-workspace" element={<UserWorkspace />} />
              <Route path="attacker-workspace" element={<AttackerWorkspace />} />
              <Route path="network-monitor" element={<NetworkMonitor />} />
              <Route path="attack-detection" element={<AttackDetection />} />
              <Route path="threat-intelligence" element={<ThreatIntelligence />} />
              <Route path="global-threat-radar" element={<GlobalThreatRadar />} />
              <Route path="user-behaviour" element={<UserBehaviour />} />
              <Route path="insider-threats" element={<InsiderThreats />} />
              <Route path="user-investigation" element={<UserInvestigation />} />
              <Route path="attack-simulator" element={<AttackSimulator />} />
              <Route path="scenario-runner" element={<ScenarioRunner />} />
              <Route path="demo-mode" element={<FacultyDemoMode />} />
              <Route path="threat-correlation" element={<ThreatCorrelation />} />
              <Route path="threat-dna" element={<ThreatDNA />} />
              <Route path="threat-memory" element={<ThreatMemory />} />
              <Route path="behaviour-evolution" element={<BehaviourEvolution />} />
              <Route path="explainable-ai" element={<ExplainableAI />} />
              <Route path="mitre-matrix" element={<MitreMatrix />} />
              <Route path="ai-copilot" element={<AICopilot />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="automated-response" element={<AutomatedResponse />} />
              <Route path="reports" element={<Reports />} />
              <Route path="settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </SOCProvider>
    </AuthProvider>
  );
}

export default App;
