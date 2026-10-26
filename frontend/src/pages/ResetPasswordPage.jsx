import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { verifyResetOtp, resetPassword, forgotPassword } from "../api/endpoints";
import Alert from "../components/Alert";
import useCooldown from "../hooks/useCooldown";

export default function ResetPasswordPage() {
  const location = useLocation();
  const navigate = useNavigate();

  const [email, setEmail] = useState(location.state?.email || "");
  const [otpCode, setOtpCode] = useState("");
  const [resetToken, setResetToken] = useState(""); // held only in memory, never logged
  const [step, setStep] = useState("otp"); // "otp" | "password"

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [cooldown, startCooldown] = useCooldown(location.state?.resendIn ?? 0);

  async function handleVerifyOtp(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await verifyResetOtp({ email: email.trim().toLowerCase(), otp_code: otpCode.trim() });
      setResetToken(res.data.reset_token);
      setStep("password");
    } catch (err) {
      setError(err.response?.data?.error || "Could not verify code.");
    } finally {
      setLoading(false);
    }
  }

  async function handleResend() {
    setError("");
    setSuccess("");
    try {
      const res = await forgotPassword({ email: email.trim().toLowerCase() });
      if (res.data?.success === false) {
        setError(res.data.message || "Could not resend the code. Please try again shortly.");
        return;
      }
      setSuccess("A new code has been sent to your email.");
      startCooldown(res.data?.resend_available_in ?? 60);
    } catch (err) {
      const data = err.response?.data;
      if (data?.retry_after) startCooldown(data.retry_after);
      setError(data?.error || "Could not resend code.");
    }
  }

  async function handleResetPassword(e) {
    e.preventDefault();
    setError("");

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      await resetPassword({
        email: email.trim().toLowerCase(),
        reset_token: resetToken,
        new_password: newPassword,
      });
      navigate("/login", {
        state: { resetSuccess: true },
      });
    } catch (err) {
      setError(err.response?.data?.error || "Could not reset password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-sm bg-white rounded-2xl shadow-sm border border-slate-200 p-8">
        {step === "otp" ? (
          <>
            <h1 className="text-xl font-bold text-slate-900 mb-1">Enter reset code</h1>
            <p className="text-sm text-slate-500 mb-6">
              Enter the 6-digit code sent to your registered email address.
              It expires in 10 minutes.
            </p>

            <Alert type="error">{error}</Alert>
            <Alert type="success">{success}</Alert>

            <form onSubmit={handleVerifyOtp} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">OTP Code</label>
                <input
                  type="text"
                  required
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ""))}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm tracking-[0.4em] text-center focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="000000"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
              >
                {loading ? "Verifying..." : "Verify code"}
              </button>
            </form>

            <button
              onClick={handleResend}
              disabled={cooldown > 0 || !email}
              className="w-full text-sm text-blue-600 hover:underline mt-4 disabled:opacity-50 disabled:no-underline"
            >
              {cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend code"}
            </button>
          </>
        ) : (
          <>
            <h1 className="text-xl font-bold text-slate-900 mb-1">Set a new password</h1>
            <p className="text-sm text-slate-500 mb-6">
              Choose a new password for <span className="font-medium">{email}</span>.
            </p>

            <Alert type="error">{error}</Alert>

            <form onSubmit={handleResetPassword} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">New password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="At least 8 characters"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Confirm new password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Re-enter new password"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium rounded-lg py-2.5 transition-colors"
              >
                {loading ? "Resetting..." : "Reset password"}
              </button>
            </form>
          </>
        )}

        <p className="text-sm text-slate-500 mt-6 text-center">
          <Link to="/login" className="text-blue-600 font-medium hover:underline">
            Back to sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
