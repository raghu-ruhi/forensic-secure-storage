import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from "recharts";
import { listEvidence } from "../api/endpoints";
import { useAuth } from "../context/AuthContext";
import StatusBadge from "../components/StatusBadge";

const STATUS_COLORS = { stored: "#94a3b8", verified: "#22c55e", tampered: "#ef4444" };

export default function DashboardPage() {
  const { user } = useAuth();
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listEvidence()
      .then((res) => setEvidence(res.data))
      .finally(() => setLoading(false));
  }, []);

  const statusCounts = evidence.reduce((acc, e) => {
    acc[e.status] = (acc[e.status] || 0) + 1;
    return acc;
  }, {});
  const pieData = Object.entries(statusCounts).map(([status, count]) => ({ name: status, value: count }));

  const casesCounts = evidence.reduce((acc, e) => {
    acc[e.case_number] = (acc[e.case_number] || 0) + 1;
    return acc;
  }, {});
  const barData = Object.entries(casesCounts).map(([case_number, count]) => ({ case_number, count }));

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Welcome back, {user?.full_name?.split(" ")[0]}</h1>
          <p className="text-sm text-slate-500 mt-1">Here's an overview of your forensic evidence store.</p>
        </div>
        <Link
          to="/evidence/upload"
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          + Upload Evidence
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <StatCard label="Total Evidence" value={evidence.length} />
        <StatCard label="Verified" value={statusCounts.verified || 0} accent="text-green-600" />
        <StatCard label="Tampered / Flagged" value={statusCounts.tampered || 0} accent="text-red-600" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-slate-700 mb-3">Evidence Status Breakdown</h2>
          {pieData.length === 0 ? (
            <EmptyChartState />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={80} label>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={STATUS_COLORS[entry.name] || "#64748b"} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <h2 className="text-sm font-semibold text-slate-700 mb-3">Evidence per Case</h2>
          {barData.length === 0 ? (
            <EmptyChartState />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="case_number" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Recent Evidence</h2>
          <Link to="/evidence" className="text-xs text-blue-600 hover:underline">View all</Link>
        </div>
        {loading ? (
          <p className="p-4 text-sm text-slate-500">Loading...</p>
        ) : evidence.length === 0 ? (
          <p className="p-4 text-sm text-slate-500">No evidence uploaded yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Case</th>
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {evidence.slice(0, 5).map((e) => (
                <tr key={e.id} className="border-t border-slate-100 hover:bg-slate-50">
                  <td className="px-4 py-2">
                    <Link to={`/evidence/${e.id}`} className="text-blue-600 hover:underline">
                      {e.case_number}
                    </Link>
                  </td>
                  <td className="px-4 py-2">{e.title}</td>
                  <td className="px-4 py-2"><StatusBadge status={e.status} /></td>
                  <td className="px-4 py-2 text-slate-500">
                    {e.created_at ? new Date(e.created_at).toLocaleString() : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, accent = "text-slate-900" }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${accent}`}>{value}</p>
    </div>
  );
}

function EmptyChartState() {
  return (
    <div className="h-[220px] flex items-center justify-center text-sm text-slate-400">
      No data yet — upload evidence to see charts.
    </div>
  );
}
