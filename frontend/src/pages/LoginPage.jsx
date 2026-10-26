import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { loginUser } from "../api/endpoints";
import { useAuth } from "../context/AuthContext";
import Alert from "../components/Alert";

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  const [form, setForm] = useState({ email: "", password: "", totp_code: "" });
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState("");
  const [success] = useState(
    location.state?.resetSuccess
      ? "Password reset successfully. Please sign in."
      : location.state?.verified
        ? "Email verified. You can now sign in."
        : ""
  );
  const [loading, setLoading] = useState(false);

  function updateField(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await loginUser(form);
      login(res.data.access_token, res.data.user);
      navigate("/dashboard");
    } catch (err) {
      const data = err.response?.data;
      if (data?.mfa_required) {
        setMfaRequired(true);
        setError("This account has MFA enabled. Enter your authenticator code.");
      } else if (data?.code === "EMAIL_NOT_VERIFIED") {
        navigate("/verify-otp", { state: { email: form.email, resendIn: 0 } });
      } else {
        setError(data?.error || "Login failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-sm bg-white rounded-2xl shadow-sm border border-slate-200 p-8">
        <h1 className="text-xl font-bold text-slate-900 mb-1">Forensic Secure Storage</h1>
        <p className="text-sm text-slate-500 mb-6">Sign in to your investigator account</p>

        <Alert type="error">{error}</Alert>
        <Alert type="success">{success}</Alert>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
            <input
              type="email"
              name="email"
              required
              value={form.email}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="you@agency.gov"
            />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-sm font-medium text-slate-700">Password</label>
              <Link to="/forgot-password" className="text-xs text-blue-600 hover:underline">
                Forgot password?
              </Link>
            </div>
            <input
              type="password"
              name="password"
              required
              value={form.password}
              onChange={updateField}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="••••••••"
            />
          </div>

          {mfaRequired && (
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Authenticator Code</label>
              <input
                type="text"
                name="totp_code"
                value={form.totp_code}
                onChange={updateField}
                maxLength={6}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="123456"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <p className="text-sm text-slate-500 mt-6 text-center">
          Don&apos;t have an account?{" "}
          <Link to="/register" className="text-blue-600 font-medium hover:underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
