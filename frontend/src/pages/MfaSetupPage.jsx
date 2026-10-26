import { useState } from "react";
import { setupMfa, confirmMfa, disableMfa } from "../api/endpoints";
import { useAuth } from "../context/AuthContext";
import Alert from "../components/Alert";

export default function MfaSetupPage() {
  const { user, refreshUser } = useAuth();
  const [qrCode, setQrCode] = useState(null);
  const [totpCode, setTotpCode] = useState("");
  const [backupCodes, setBackupCodes] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSetup() {
    setError("");
    setLoading(true);
    try {
      const res = await setupMfa();
      setQrCode(res.data.qr_code);
    } catch (err) {
      setError(err.response?.data?.error || "Could not start MFA setup");
    } finally {
      setLoading(false);
    }
  }

  async function handleConfirm(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await confirmMfa({ totp_code: totpCode });
      setBackupCodes(res.data.backup_codes);
      await refreshUser();
    } catch (err) {
      setError(err.response?.data?.error || "Invalid code");
    } finally {
      setLoading(false);
    }
  }

  async function handleDisable(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await disableMfa({ totp_code: totpCode });
      setQrCode(null);
      setBackupCodes(null);
      setTotpCode("");
      await refreshUser();
    } catch (err) {
      setError(err.response?.data?.error || "Could not disable MFA");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md">
      <h1 className="text-2xl font-bold text-slate-900 mb-1">Multi-Factor Authentication</h1>
      <p className="text-sm text-slate-500 mb-6">
        Add an authenticator app (Google Authenticator, Authy, etc.) as a second login factor.
      </p>

      <Alert type="error">{error}</Alert>

      {user?.mfa_enabled ? (
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <Alert type="success">MFA is currently enabled on your account.</Alert>
          <form onSubmit={handleDisable} className="space-y-3">
            <label className="block text-sm font-medium text-slate-700">
              Enter your current authenticator code to disable MFA
            </label>
            <input
              type="text"
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="123456"
            />
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5"
            >
              Disable MFA
            </button>
          </form>
        </div>
      ) : backupCodes ? (
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <Alert type="success">MFA enabled! Save these backup codes somewhere safe.</Alert>
          <div className="grid grid-cols-2 gap-2 font-mono text-sm bg-slate-50 rounded-lg p-4">
            {backupCodes.map((code) => (
              <span key={code}>{code}</span>
            ))}
          </div>
          <p className="text-xs text-slate-400 mt-3">
            Each code works once. They will not be shown again.
          </p>
        </div>
      ) : qrCode ? (
        <div className="bg-white border border-slate-200 rounded-xl p-6 text-center">
          <img src={qrCode} alt="TOTP QR Code" className="mx-auto rounded-lg border border-slate-200" />
          <form onSubmit={handleConfirm} className="space-y-3 mt-4 text-left">
            <label className="block text-sm font-medium text-slate-700">
              Enter the 6-digit code from your app to confirm
            </label>
            <input
              type="text"
              maxLength={6}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="123456"
            />
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5"
            >
              Confirm & Enable
            </button>
          </form>
        </div>
      ) : (
        <button
          onClick={handleSetup}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg px-4 py-2.5"
        >
          {loading ? "Generating..." : "Set Up MFA"}
        </button>
      )}
    </div>
  );
}
