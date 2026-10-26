import apiClient from "../api/client";

export function formatBytes(n) {
  if (n === null || n === undefined) return "-";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value < 10 ? 2 : 1)} ${units[i]}`;
}

export function extensionOf(name = "") {
  const dot = name.lastIndexOf(".");
  return dot > -1 ? name.slice(dot + 1).toLowerCase() : "";
}

/** Axios errors for blob requests carry the JSON error body as a Blob; unwrap it. */
export async function errorMessage(err, fallback) {
  const data = err?.response?.data;
  if (data instanceof Blob) {
    try {
      const parsed = JSON.parse(await data.text());
      return parsed.error || fallback;
    } catch {
      return fallback;
    }
  }
  return data?.error || fallback;
}

// Browsers may render ONLY these types inline; the server sends the same list.
const SAFE_PREVIEW_TYPES = /^(image\/(png|jpeg|gif|webp|bmp)|application\/pdf|text\/plain)/;

/**
 * Fetch evidence through the authenticated API (the JWT travels in the
 * Authorization header, never in a URL) and return a Blob.
 */
export async function fetchEvidenceBlob(evidenceId, mode /* "view" | "download" */) {
  const res = await apiClient.get(`/evidence/${evidenceId}/${mode}`, { responseType: "blob" });
  return res;
}

export async function downloadEvidence(evidence) {
  const res = await fetchEvidenceBlob(evidence.id, "download");
  const url = window.URL.createObjectURL(res.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = evidence.original_filename || "evidence.bin";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => window.URL.revokeObjectURL(url), 10000);
  return res.headers["x-evidence-sha256"];
}

/** Returns {url, type, text?}; the caller must revoke `url`. */
export async function loadPreview(evidence) {
  const res = await fetchEvidenceBlob(evidence.id, "view");
  const type = (res.headers["content-type"] || "").toLowerCase();
  if (!SAFE_PREVIEW_TYPES.test(type)) {
    throw new Error("This file type cannot be previewed safely. Use Download instead.");
  }
  if (type.startsWith("text/plain")) {
    const full = await res.data.text();
    // Rendered by React as text (never as HTML); cap what we display.
    return { type: "text", text: full.slice(0, 200000), truncated: full.length > 200000 };
  }
  // Re-wrap with the verified type so the browser cannot be talked into another one.
  const blob = new Blob([res.data], { type: type.split(";")[0] });
  return { type: type.startsWith("image/") ? "image" : "pdf", url: window.URL.createObjectURL(blob) };
}
