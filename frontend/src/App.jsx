import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";

import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import OtpVerificationPage from "./pages/OtpVerificationPage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import DashboardPage from "./pages/DashboardPage";
import UploadEvidencePage from "./pages/UploadEvidencePage";
import EvidenceListPage from "./pages/EvidenceListPage";
import EvidenceDetailsPage from "./pages/EvidenceDetailsPage";
import AuditLogsPage from "./pages/AuditLogsPage";
import InvigilatorsPage from "./pages/InvigilatorsPage";
import PeerStoragePage from "./pages/PeerStoragePage";
import MfaSetupPage from "./pages/MfaSetupPage";
import KeysPage from "./pages/KeysPage";
import SettingsPage from "./pages/SettingsPage";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/verify-otp" element={<OtpVerificationPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />

          <Route
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/evidence/upload" element={<UploadEvidencePage />} />
            <Route path="/evidence" element={<EvidenceListPage />} />
            <Route path="/evidence/:evidenceId" element={<EvidenceDetailsPage />} />
            <Route path="/keys" element={<KeysPage />} />
            <Route path="/peer-storage" element={<PeerStoragePage />} />
            <Route path="/mfa-setup" element={<MfaSetupPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route
              path="/audit-logs"
              element={
                <ProtectedRoute adminOnly>
                  <AuditLogsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/invigilators"
              element={
                <ProtectedRoute adminOnly>
                  <InvigilatorsPage />
                </ProtectedRoute>
              }
            />
          </Route>

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
