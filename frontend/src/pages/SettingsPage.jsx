import { useAuth } from "../context/AuthContext";

export default function SettingsPage() {
  const { user } = useAuth();

  return (
    <div className="max-w-md">
      <h1 className="text-2xl font-bold text-slate-900 mb-6">Settings</h1>

      <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
        <Row label="Full Name" value={user?.full_name} />
        <Row label="Email" value={user?.email} />
        <Row label="Role" value={user?.role} />
        <Row label="Email Verified" value={user?.is_email_verified ? "Yes" : "No"} />
        <Row label="MFA Enabled" value={user?.mfa_enabled ? "Yes" : "No"} />
        <Row label="Account Created" value={user?.created_at ? new Date(user.created_at).toLocaleString() : "-"} />
      </div>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between text-sm border-b border-slate-50 pb-2 last:border-0 last:pb-0">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-800 font-medium">{value}</span>
    </div>
  );
}
