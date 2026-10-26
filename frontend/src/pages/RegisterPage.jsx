import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { registerUser } from "../api/endpoints";
import Alert from "../components/Alert";

export default function RegisterPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    full_name: "",
    email: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function updateField(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      // The backend always creates this account as an Investigator - role
      // is never accepted from the client. Admin accounts can only be
      // created by an existing Admin (see /invigilators) or via the
      // server-side create_admin.py / ADMIN_EMAIL bootstrap.
      const res = await registerUser(form);
      navigate("/verify-otp", {
        state: { email: form.email, resendIn: res.data?.resend_available_in ?? 60 },
      });
    } catch (err) {
      const data = err.response?.data;
      if (data?.account_created) {
        // The account exists but the e-mail could not be sent. Do not pretend
        // it was: go to the verification page with the real problem shown, so
        // the user can press "Resend code" once mail is fixed.
        navigate("/verify-otp", {
          state: { email: form.email, resendIn: 0, notice: data.error + (data.mail_error ? ` (${data.mail_error})` : "") },
        });
        return;
      }
      setError(data?.error || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-sm bg-white rounded-2xl shadow-sm border border-slate-200 p-8">
        <h1 className="text-xl font-bold text-slate-900 mb-1">Create an account</h1>
        <p className="text-sm text-slate-500 mb-6">Register as an investigator</p>

        <Alert type="error">{error}</Alert>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Full Name</label>
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
            <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
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
            <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
            <input
              type="password"
              name="password"
              required
              minLength={8}
              value={form.password}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-slate-400 mt-1">At least 8 characters</p>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
          >
            {loading ? "Creating account..." : "Create Account"}
          </button>
        </form>

        <p className="text-sm text-slate-500 mt-6 text-center">
          Already have an account?{" "}
          <Link to="/login" className="text-blue-600 font-medium hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
