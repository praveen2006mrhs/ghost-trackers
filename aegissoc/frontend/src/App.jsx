import React, { useState } from 'react';
import Navbar from './components/common/Navbar';
import Sidebar from './components/common/Sidebar';
import OverviewDashboard from './components/dashboard/OverviewDashboard';
import VulnScannerView from './components/modules/VulnScannerView';
import ArchitectureReviewerView from './components/modules/ArchitectureReviewerView';
import ForensicsView from './components/modules/ForensicsView';
import ThreatModelView from './components/modules/ThreatModelView';
import SecurityTestingView from './components/modules/SecurityTestingView';
import MalwareTriageView from './components/modules/MalwareTriageView';

export default function App() {
  const [currentView, setCurrentView] = useState('overview');

  const renderActiveView = () => {
    switch (currentView) {
      case 'overview':
        return <OverviewDashboard onNavigate={setCurrentView} />;
      case 'vuln':
        return <VulnScannerView />;
      case 'architecture':
        return <ArchitectureReviewerView />;
      case 'forensics':
        return <ForensicsView />;
      case 'threat_model':
        return <ThreatModelView />;
      case 'security_tests':
        return <SecurityTestingView />;
      case 'malware':
        return <MalwareTriageView />;
      default:
        return <OverviewDashboard onNavigate={setCurrentView} />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-soc-bg bg-grid-cyber">
      {/* Top Navbar */}
      <Navbar activeModule={currentView} onSelectModule={setCurrentView} />

      {/* Main Workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar currentView={currentView} onSelectView={setCurrentView} />

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-6 max-w-7xl mx-auto w-full">
          {renderActiveView()}
        </main>
      </div>
    </div>
  );
}
