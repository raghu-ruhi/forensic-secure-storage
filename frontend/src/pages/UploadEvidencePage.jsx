import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { uploadEvidence, getUploadRules } from "../api/endpoints";
import Alert from "../components/Alert";
import { extensionOf, formatBytes } from "../utils/files";

export default function UploadEvidencePage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ case_number: "", title: "", description: "" });
  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [rules, setRules] = useState(null); // {max_upload_mb, allowed_extensions} from the backend

  useEffect(() => {
    getUploadRules().then((res) => setRules(res.data)).catch(() => setRules(null));
  }, []);

  // Mirrors the backend rules for fast feedback; the server re-checks everything.
  function checkFile(f) {
    if (!f) return "";
    if (f.size === 0) return "The selected file is empty.";
    if (rules) {
      const ext = extensionOf(f.name);
      if (!ext || !rules.allowed_extensions.includes(ext)) {
        return `Files of type ".${ext || "(none)"}" are not accepted.`;
      }
      if (f.size > rules.max_upload_mb * 1024 * 1024) {
        return `The file is ${formatBytes(f.size)}; the maximum is ${rules.max_upload_mb} MB.`;
      }
    }
    return "";
  }

  function handleFileChange(e) {
    const f = e.target.files[0] || null;
    setFile(f);
    setError(checkFile(f));
  }

  function updateField(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (!file) {
      setError("Please select a file to upload.");
      return;
    }
    const problem = checkFile(file);
    if (problem) {
      setError(problem);
      return;
    }
    setLoading(true);
    setProgress(0);
    try {
      const formData = new FormData();
      formData.append("case_number", form.case_number);
      formData.append("title", form.title);
      formData.append("description", form.description);
      formData.append("file", file);

      const res = await uploadEvidence(formData, (evt) => {
        if (evt.total) setProgress(Math.round((evt.loaded * 100) / evt.total));
      });
      navigate(`/evidence/${res.data.evidence.id}`);
    } catch (err) {
      setError(err.response?.data?.error || "Upload failed. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-xl">
      <h1 className="text-2xl font-bold text-slate-900 mb-1">Upload Evidence</h1>
      <p className="text-sm text-slate-500 mb-6">
        The file will be hashed (SHA-256), encrypted with an EEO-optimized AES-256 key,
        and replicated to 3 peer storage nodes.
      </p>

      <Alert type="error">{error}</Alert>

      <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Case Number</label>
          <input
            type="text"
            name="case_number"
            required
            value={form.case_number}
            onChange={updateField}
            placeholder="CASE-2026-001"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Evidence Title</label>
          <input
            type="text"
            name="title"
            required
            value={form.title}
            onChange={updateField}
            placeholder="Suspect laptop RAM dump"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Description</label>
          <textarea
            name="description"
            rows={3}
            value={form.description}
            onChange={updateField}
            placeholder="Captured during raid, chain of custody starts here..."
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Evidence File</label>
          <input
            type="file"
            required
            onChange={handleFileChange}
            className="w-full text-sm text-slate-600 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-blue-50 file:text-blue-700 file:text-sm hover:file:bg-blue-100"
          />
          {rules && (
            <p className="text-xs text-slate-400 mt-1">
              Max {rules.max_upload_mb} MB. Allowed: {rules.allowed_extensions.map((e) => `.${e}`).join(" ")}
            </p>
          )}
          {file && <p className="text-xs text-slate-500 mt-1">{file.name} — {formatBytes(file.size)}</p>}
        </div>

        {loading && (
          <div>
            <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div className="h-full bg-blue-600 transition-all" style={{ width: `${progress}%` }} />
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {progress < 100 ? `Uploading... ${progress}%` : "Upload complete — hashing, encrypting and replicating..."}
            </p>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
        >
          {loading ? "Encrypting & Uploading..." : "Upload & Encrypt Evidence"}
        </button>
      </form>
    </div>
  );
}
