import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listEvidence } from "../api/endpoints";
import Alert from "../components/Alert";
import FilePreview from "../components/FilePreview";
import StatusBadge from "../components/StatusBadge";
import { downloadEvidence, errorMessage, formatBytes } from "../utils/files";

export default function EvidenceListPage() {
  const [evidence, setEvidence] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState("");

  async function handleDownload(item) {
    setError("");
    setBusyId(item.id);
    try {
      await downloadEvidence(item);
    } catch (err) {
      setError(await errorMessage(err, "Download failed."));
    } finally {
      setBusyId("");
    }
  }

  useEffect(() => {
    listEvidence()
      .then((res) => setEvidence(res.data))
      .finally(() => setLoading(false));
  }, []);

  const filtered = evidence.filter((e) =>
    `${e.case_number} ${e.title} ${e.original_filename} ${e.id}`.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Evidence</h1>
        <Link
          to="/evidence/upload"
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          + Upload Evidence
        </Link>
      </div>

      <input
        type="text"
        placeholder="Search by case, title, file name or evidence ID..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-full max-w-sm rounded-lg border border-slate-300 px-3 py-2 text-sm mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />

      <Alert type="error">{error}</Alert>
      {preview && (
        <div className="mb-4">
          <FilePreview evidence={preview} onClose={() => setPreview(null)} />
        </div>
      )}

      <div className="bg-white border border-slate-200 rounded-xl overflow-x-auto">
        {loading ? (
          <p className="p-4 text-sm text-slate-500">Loading...</p>
        ) : filtered.length === 0 ? (
          <p className="p-4 text-sm text-slate-500">No evidence found.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Evidence ID</th>
                <th className="px-4 py-2 font-medium">Case</th>
                <th className="px-4 py-2 font-medium">File</th>
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Size</th>
                <th className="px-4 py-2 font-medium">SHA-256</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Nodes</th>
                <th className="px-4 py-2 font-medium">Uploaded</th>
                <th className="px-4 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.id} className="border-t border-slate-100 hover:bg-slate-50">
                  <td className="px-4 py-2 font-mono text-xs">
                    <Link to={`/evidence/${e.id}`} className="text-blue-600 hover:underline" title={e.id}>
                      {e.id.slice(0, 8)}
                    </Link>
                  </td>
                  <td className="px-4 py-2">{e.case_number}</td>
                  <td className="px-4 py-2 max-w-[14rem] truncate" title={e.title}>
                    {e.original_filename}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500 uppercase">{e.file_extension || "-"}</td>
                  <td className="px-4 py-2 text-slate-500 whitespace-nowrap">{formatBytes(e.file_size_bytes)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">
                    {e.sha256_hash.slice(0, 12)}...
                  </td>
                  <td className="px-4 py-2"><StatusBadge status={e.status} /></td>
                  <td className="px-4 py-2 text-xs text-slate-500">{e.replicated_nodes?.length || 0}/3</td>
                  <td className="px-4 py-2 text-slate-500">
                    {e.created_at ? new Date(e.created_at).toLocaleDateString() : "-"}
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap space-x-3">
                    {e.previewable ? (
                      <button onClick={() => setPreview(e)} className="text-blue-600 hover:underline">View</button>
                    ) : (
                      <span className="text-slate-300" title="Preview not available for this file type">View</span>
                    )}
                    <button
                      onClick={() => handleDownload(e)}
                      disabled={busyId === e.id}
                      className="text-blue-600 hover:underline disabled:opacity-50"
                    >
                      {busyId === e.id ? "..." : "Download"}
                    </button>
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
