import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
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
import Settings from './pages/Settings';

function AppLayout() {
  return (
    <div className="bg-surface text-on-surface antialiased min-h-screen selection:bg-primary selection:text-on-primary">
      <Sidebar />

      <div className="pl-72">
        <Topbar />

        <main className="w-full pt-20 bg-surface min-h-screen">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/run-scan" element={<RunScan />} />
            <Route path="/live-scan" element={<LiveScan />} />
            <Route path="/results" element={<Results />} />
            <Route path="/findings/:id" element={<FindingDetails />} />
            {/* Backward compatibility alias in case users or links use /results/:id */}
            <Route path="/results/:id" element={<FindingDetails />} />
            <Route path="/test-cases" element={<TestCases />} />
            <Route path="/target" element={<Target />} />
            <Route path="/reports" element={<Reports />} />
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