import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { useState } from 'react';
import { StatusProvider } from './context/StatusContext';

import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';

import Dashboard from './pages/Dashboard';
import RunScan from './pages/RunScan';
import LiveScan from './pages/LiveScan';
import Results from './pages/Results';
import FindingDetails from './pages/FindingDetails';
import TestCases from './pages/TestCases';
import Target from './pages/Target';
import Reports from './pages/Reports';
import ScanHistory from './pages/ScanHistory';
import Settings from './pages/Settings';

function AppLayout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="min-h-screen overflow-x-hidden bg-surface text-on-surface antialiased selection:bg-primary selection:text-on-primary">
      {mobileNavOpen && (
        <button
          type="button"
          className="fixed inset-0 z-40 bg-slate-950/30 md:hidden"
          aria-label="Close navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      )}
      <Sidebar
        open={mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
      />

      <div className="lg:pl-72">
        <Topbar onMenuClick={() => setMobileNavOpen(true)} />

        <main className="min-h-screen w-full overflow-x-hidden bg-surface pt-20">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/run-scan" element={<RunScan />} />
            <Route path="/live-scan" element={<LiveScan />} />
            <Route path="/results" element={<Results />} />
            <Route path="/findings" element={<Results />} />
            <Route path="/findings/:id" element={<FindingDetails />} />
            {/* Backward compatibility alias in case users or links use /results/:id */}
            <Route path="/results/:id" element={<FindingDetails />} />
            <Route path="/test-cases" element={<TestCases />} />
            <Route path="/target" element={<Target />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/analytics" element={<Reports />} />
            <Route path="/scan-history" element={<ScanHistory />} />
            <Route path="/settings" element={<Settings />} />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <StatusProvider>
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </StatusProvider>
  );
}

export default App;