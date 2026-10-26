import { useEffect, useState } from "react";
import { listAuditLogs } from "../api/endpoints";
import Alert from "../components/Alert";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAuditLogs(200)
      .then((res) => setLogs(res.data))
      .catch((err) => setError(err.response?.data?.error || "Failed to load audit logs"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-slate-900 mb-1">Audit Logs</h1>
      <p className="text-sm text-slate-500 mb-6">System-wide chain-of-custody activity log.</p>

      <Alert type="error">{error}</Alert>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        {loading ? (
          <p className="p-4 text-sm text-slate-500">Loading...</p>
        ) : logs.length === 0 ? (
          <p className="p-4 text-sm text-slate-500">No audit log entries yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Actor</th>
                <th className="px-4 py-2 font-medium">Resource</th>
                <th className="px-4 py-2 font-medium">IP</th>
                <th className="px-4 py-2 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-t border-slate-100 hover:bg-slate-50">
                  <td className="px-4 py-2 font-medium text-slate-800">{log.action}</td>
                  <td className="px-4 py-2 text-slate-600">{log.actor_email || "-"}</td>
                  <td className="px-4 py-2 text-slate-500 text-xs">
                    {log.resource_type ? `${log.resource_type}:${log.resource_id?.slice(0, 8)}` : "-"}
                  </td>
                  <td className="px-4 py-2 text-slate-500 text-xs">{log.ip_address || "-"}</td>
                  <td className="px-4 py-2 text-slate-500">{new Date(log.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
