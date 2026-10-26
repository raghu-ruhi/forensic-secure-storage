import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { forgotPassword } from "../api/endpoints";
import Alert from "../components/Alert";

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await forgotPassword({ email: email.trim().toLowerCase() });
      if (res.data?.success === false) {
        // Backend generated the code but could not email it - don't send
        // the user to the OTP screen to wait for something that never
        // arrived. Surface the failure instead.
        setError(res.data.message || "Could not send the reset code. Please try again shortly.");
        return;
      }
      // Move straight to the OTP + new-password step. We never read or show
      // the OTP here - it only ever exists in the email that was just sent.
      navigate("/reset-password", {
        state: { email: email.trim().toLowerCase(), resendIn: res.data?.resend_available_in ?? 60 },
      });
    } catch (err) {
      // 502 = the e-mail really could not be sent; 429 = cooldown / rate limit.
      setError(err.response?.data?.error || "Could not send reset code. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-sm bg-white rounded-2xl shadow-sm border border-slate-200 p-8">
        <h1 className="text-xl font-bold text-slate-900 mb-1">Forgot password</h1>
        <p className="text-sm text-slate-500 mb-6">
          Enter your registered email address and we&apos;ll send you a one-time
          code to reset your password.
        </p>

        <Alert type="error">{error}</Alert>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="you@agency.gov"
              autoFocus
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
          >
            {loading ? "Sending..." : "Send reset code"}
          </button>
        </form>

        <p className="text-sm text-slate-500 mt-6 text-center">
          Remembered your password?{" "}
          <Link to="/login" className="text-blue-600 font-medium hover:underline">
            Back to sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
