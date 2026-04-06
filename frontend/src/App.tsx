import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ErrorBoundary } from './components/shared/ErrorBoundary';
import { ToastContainer } from './components/shared/NotificationToast';
import { AppLayout } from './components/layout/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { ScansPage } from './pages/ScansPage';
import { NewScanPage } from './pages/NewScanPage';
import { LiveScanPage } from './pages/LiveScanPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { AuditPage } from './pages/AuditPage';
import { ReportsPage } from './pages/ReportsPage';
import { ExportPage } from './pages/ExportPage';
import { ComparePage } from './pages/ComparePage';
import { SettingsPage } from './pages/SettingsPage';
import { ProfilesPage } from './pages/ProfilesPage';
import { WhitelistPage } from './pages/WhitelistPage';
import { MonitoringPage } from './pages/MonitoringPage';
import { AgentToolsPage } from './pages/AgentToolsPage';
import { LoginPage } from './pages/LoginPage';
import { useAuthStore } from './stores/authStore';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
});

export default function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        {isAuthenticated ? (
          <BrowserRouter>
            <Routes>
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="/scans" element={<ScansPage />} />
                <Route path="/scans/new" element={<NewScanPage />} />
                <Route path="/scans/:id/live" element={<LiveScanPage />} />
                <Route path="/scans/:id" element={<ScanDetailPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/findings/:id" element={<FindingDetailPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/export" element={<ExportPage />} />
                <Route path="/compare" element={<ComparePage />} />
                <Route path="/profiles" element={<ProfilesPage />} />
                <Route path="/whitelist" element={<WhitelistPage />} />
                <Route path="/monitoring" element={<MonitoringPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/agent-tools" element={<AgentToolsPage />} />
              </Route>
            </Routes>
          </BrowserRouter>
        ) : (
          <LoginPage />
        )}
        <ToastContainer />
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
