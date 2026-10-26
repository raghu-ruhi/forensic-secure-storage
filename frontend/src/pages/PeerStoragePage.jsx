import { useEffect, useState } from "react";
import { listEvidence, checkEvidenceNodes } from "../api/endpoints";
import Alert from "../components/Alert";

const NODES = ["node_a", "node_b", "node_c"];

export default function PeerStoragePage() {
  const [evidence, setEvidence] = useState([]);
  const [checks, setChecks] = useState({});
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listEvidence()
      .then((res) => setEvidence(res.data))
      .catch((err) => setError(err.response?.data?.error || "Failed to load evidence"))
      .finally(() => setLoading(false));
  }, []);

  async function checkOne(id) {
    setChecks((prev) => ({ ...prev, [id]: { loading: true } }));
    try {
      const res = await checkEvidenceNodes(id);
      setChecks((prev) => ({ ...prev, [id]: { loading: false, data: res.data } }));
    } catch (err) {
      setChecks((prev) => ({
        ...prev,
        [id]: { loading: false, error: err.response?.data?.error || "Check failed" },
      }));
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-slate-900 mb-1">Distributed Peer Storage</h1>
      <p className="text-sm text-slate-500 mb-6">
        Every encrypted evidence file is replicated to three simulated peer nodes
        (node_a, node_b, node_c). Consistency checks compare ciphertext hashes across nodes.
      </p>

      <Alert type="error">{error}</Alert>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        {loading ? (
          <p className="p-4 text-sm text-slate-500">Loading...</p>
        ) : evidence.length === 0 ? (
          <p className="p-4 text-sm text-slate-500">No evidence uploaded yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Case / Title</th>
                {NODES.map((n) => (
                  <th key={n} className="px-4 py-2 font-medium">{n}</th>
                ))}
                <th className="px-4 py-2 font-medium">Consistent</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((e) => {
                const check = checks[e.id];
                return (
                  <tr key={e.id} className="border-t border-slate-100">
                    <td className="px-4 py-2">
                      <p className="font-medium text-slate-800">{e.case_number}</p>
                      <p className="text-xs text-slate-500">{e.title}</p>
                    </td>
                    {NODES.map((n) => (
                      <td key={n} className="px-4 py-2">
                        {e.replicated_nodes.includes(n) ? (
                          <span className="text-green-600">●</span>
                        ) : (
                          <span className="text-slate-300">○</span>
                        )}
                      </td>
                    ))}
                    <td className="px-4 py-2">
                      {check?.loading && <span className="text-slate-400">checking...</span>}
                      {check?.data && (
                        check.data.consistent ? (
                          <span className="text-green-600 font-medium">✓ consistent</span>
                        ) : (
                          <span className="text-red-600 font-medium">✗ mismatch</span>
                        )
                      )}
                      {check?.error && <span className="text-red-500 text-xs">{check.error}</span>}
                    </td>
                    <td className="px-4 py-2">
                      <button
                        onClick={() => checkOne(e.id)}
                        className="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-2.5 py-1 rounded-md"
                      >
                        Check
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
