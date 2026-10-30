import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { ThreatNotificationToast } from '../common/ThreatNotificationToast';

export const Layout = () => {
  return (
    <div className="min-h-screen bg-[#0a0e17] text-[#f3f4f6] flex relative">
      {/* Real-time Threat Alert Toast */}
      <ThreatNotificationToast />

      {/* Fixed Left Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col pl-64 min-w-0">
        <Topbar />
        <main className="flex-1 p-6 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
