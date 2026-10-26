import { useEffect, useState } from "react";
import {
  listInvigilators,
  createInvigilator,
  deleteInvigilator,
  reactivateInvigilator,
} from "../api/endpoints";
import Alert from "../components/Alert";

export default function InvigilatorsPage() {
  const [invigilators, setInvigilators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");

  const [form, setForm] = useState({ full_name: "", email: "", password: "" });
  const [formError, setFormError] = useState("");
  const [formSuccess, setFormSuccess] = useState("");
  const [creating, setCreating] = useState(false);

  const [actionError, setActionError] = useState("");
  const [pendingId, setPendingId] = useState(null);

  function loadInvigilators() {
    setLoading(true);
    listInvigilators()
      .then((res) => setInvigilators(res.data))
      .catch((err) => setListError(err.response?.data?.error || "Failed to load invigilators"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadInvigilators();
  }, []);

  function updateField(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleCreate(e) {
    e.preventDefault();
    setFormError("");
    setFormSuccess("");
    setCreating(true);
    try {
      await createInvigilator(form);
      setFormSuccess(`Invigilator account created for ${form.email}.`);
      setForm({ full_name: "", email: "", password: "" });
      loadInvigilators();
    } catch (err) {
      setFormError(err.response?.data?.error || "Could not create invigilator account.");
    } finally {
      setCreating(false);
    }
  }

  async function handleDeactivate(inv) {
    if (!window.confirm(`Deactivate ${inv.email}? They will no longer be able to log in.`)) return;
    setActionError("");
    setPendingId(inv.id);
    try {
      await deleteInvigilator(inv.id);
      loadInvigilators();
    } catch (err) {
      setActionError(err.response?.data?.error || "Could not deactivate this account.");
    } finally {
      setPendingId(null);
    }
  }

  async function handleReactivate(inv) {
    setActionError("");
    setPendingId(inv.id);
    try {
      await reactivateInvigilator(inv.id);
      loadInvigilators();
    } catch (err) {
      setActionError(err.response?.data?.error || "Could not reactivate this account.");
    } finally {
      setPendingId(null);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-slate-900 mb-1">Invigilators</h1>
      <p className="text-sm text-slate-500 mb-6">
        Create and manage Invigilator accounts. Only an Admin can create, view, or deactivate
        these accounts.
      </p>

      <div className="bg-white border border-slate-200 rounded-xl p-6 mb-6">
        <h2 className="text-sm font-semibold text-slate-800 mb-4">Create a new invigilator</h2>
        <Alert type="error">{formError}</Alert>
        <Alert type="success">{formSuccess}</Alert>
        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Full name</label>
            <input
              type="text"
              name="full_name"
              required
              value={form.full_name}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Email</label>
            <input
              type="email"
              name="email"
              required
              value={form.email}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Password</label>
            <input
              type="password"
              name="password"
              required
              minLength={8}
              value={form.password}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="At least 8 characters"
            />
          </div>
          <div className="sm:col-span-3">
            <button
              type="submit"
              disabled={creating}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors"
            >
              {creating ? "Creating..." : "Create invigilator"}
            </button>
          </div>
        </form>
      </div>

      <Alert type="error">{listError}</Alert>
      <Alert type="error">{actionError}</Alert>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        {loading ? (
          <p className="p-4 text-sm text-slate-500">Loading...</p>
        ) : invigilators.length === 0 ? (
          <p className="p-4 text-sm text-slate-500">No invigilators yet - create one above.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Created</th>
                <th className="px-4 py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {invigilators.map((inv) => (
                <tr key={inv.id} className="border-t border-slate-100 hover:bg-slate-50">
                  <td className="px-4 py-2 font-medium text-slate-800">{inv.full_name}</td>
                  <td className="px-4 py-2 text-slate-600">{inv.email}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full ${
                        inv.is_active
                          ? "bg-green-50 text-green-700"
                          : "bg-slate-100 text-slate-500"
                      }`}
                    >
                      {inv.is_active ? "Active" : "Deactivated"}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-500">
                    {inv.created_at ? new Date(inv.created_at).toLocaleString() : "-"}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {inv.is_active ? (
                      <button
                        onClick={() => handleDeactivate(inv)}
                        disabled={pendingId === inv.id}
                        className="text-red-600 hover:underline text-sm disabled:opacity-50"
                      >
                        Deactivate
                      </button>
                    ) : (
                      <button
                        onClick={() => handleReactivate(inv)}
                        disabled={pendingId === inv.id}
                        className="text-blue-600 hover:underline text-sm disabled:opacity-50"
                      >
                        Reactivate
                      </button>
                    )}
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
