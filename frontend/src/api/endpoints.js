import apiClient from "./client";

// ---- Auth ----
export const registerUser = (payload) => apiClient.post("/auth/register", payload);
export const verifyOtp = (payload) => apiClient.post("/auth/verify-otp", payload);
export const resendOtp = (payload) => apiClient.post("/auth/resend-otp", payload);
export const loginUser = (payload) => apiClient.post("/auth/login", payload);
export const fetchMe = () => apiClient.get("/auth/me");
export const forgotPassword = (payload) => apiClient.post("/auth/forgot-password", payload);
export const verifyResetOtp = (payload) => apiClient.post("/auth/verify-reset-otp", payload);
export const resetPassword = (payload) => apiClient.post("/auth/reset-password", payload);

// Admin-only: invigilator (investigator) account management.
export const listInvigilators = () => apiClient.get("/admin/invigilators");
export const createInvigilator = (payload) => apiClient.post("/admin/invigilators", payload);
export const deleteInvigilator = (id) => apiClient.delete(`/admin/invigilators/${id}`);
export const reactivateInvigilator = (id) => apiClient.post(`/admin/invigilators/${id}/reactivate`);

// ---- Evidence ----
export const uploadEvidence = (formData, onUploadProgress) =>
  apiClient.post("/evidence/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress,
  });
export const getUploadRules = () => apiClient.get("/evidence/upload-rules");
export const listEvidence = () => apiClient.get("/evidence");
export const getEvidence = (id) => apiClient.get(`/evidence/${id}`);
export const verifyEvidence = (id) => apiClient.post(`/evidence/${id}/verify`);
export const getEvidenceLedger = (id) => apiClient.get(`/evidence/${id}/ledger`);
export const checkEvidenceNodes = (id) => apiClient.get(`/evidence/${id}/nodes`);
export const rotateEvidenceKey = (id) => apiClient.post(`/evidence/${id}/rotate-key`);

// ---- Signatures ----
export const signEvidence = (id) => apiClient.post(`/signatures/${id}/sign`);
export const verifyEvidenceSignatures = (id) => apiClient.get(`/signatures/${id}/verify`);

// ---- Reports ----
export const downloadReportUrl = (id, baseURL) =>
  `${baseURL || apiClient.defaults.baseURL}/reports/${id}`;

// ---- Audit logs ----
export const listAuditLogs = (limit = 100) => apiClient.get(`/audit-logs?limit=${limit}`);
export const listEvidenceAuditLogs = (evidenceId) =>
  apiClient.get(`/audit-logs/evidence/${evidenceId}`);

// ---- MFA ----
export const setupMfa = () => apiClient.post("/mfa/setup");
export const confirmMfa = (payload) => apiClient.post("/mfa/confirm", payload);
export const disableMfa = (payload) => apiClient.post("/mfa/disable", payload);
export const verifyBackupCode = (payload) => apiClient.post("/mfa/verify-backup-code", payload);
