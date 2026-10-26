import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  getEvidence, verifyEvidence, getEvidenceLedger, rotateEvidenceKey,
  signEvidence, verifyEvidenceSignatures, downloadReportUrl,
} from "../api/endpoints";
import apiClient from "../api/client";
import Alert from "../components/Alert";
import FilePreview from "../components/FilePreview";
import { downloadEvidence, errorMessage, formatBytes } from "../utils/files";
import StatusBadge from "../components/StatusBadge";

export default function EvidenceDetailsPage() {
  const { evidenceId } = useParams();
  const [evidence, setEvidence] = useState(null);
  const [ledger, setLedger] = useState([]);
  const [signatures, setSignatures] = useState([]);
  const [verifyResult, setVerifyResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [downloadInfo, setDownloadInfo] = useState("");

  async function loadAll() {
    const [evRes, ledgerRes] = await Promise.all([
      getEvidence(evidenceId),
      getEvidenceLedger(evidenceId),
    ]);
    setEvidence(evRes.data);
    setLedger(ledgerRes.data.blocks);
    try {
      const sigRes = await verifyEvidenceSignatures(evidenceId);
      setSignatures(sigRes.data.signatures);
    } catch {
      setSignatures([]);
    }
  }

  useEffect(() => {
    loadAll().catch((err) => setError(err.response?.data?.error || "Failed to load evidence"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceId]);

  async function handleVerify() {
    setBusy("verify");
    setError("");
    try {
      const res = await verifyEvidence(evidenceId);
      setVerifyResult(res.data);
      await loadAll();
    } catch (err) {
      setError(err.response?.data?.error || "Verification failed");
    } finally {
      setBusy("");
    }
  }

  async function handleDownload() {
    setBusy("download");
    setError("");
    setDownloadInfo("");
    try {
      const sha = await downloadEvidence(evidence);
      setDownloadInfo(`Integrity verified before release. SHA-256: ${sha}`);
      await loadAll(); // the download is recorded on the ledger
    } catch (err) {
      setError(await errorMessage(err, "Download failed"));
      await loadAll().catch(() => {}); // status may now be flagged as tampered
    } finally {
      setBusy("");
    }
  }

  async function handleSign() {
    setBusy("sign");
    setError("");
    try {
      await signEvidence(evidenceId);
      await loadAll();
    } catch (err) {
      setError(err.response?.data?.error || "Signing failed");
    } finally {
      setBusy("");
    }
  }

  async function handleRotateKey() {
    setBusy("rotate");
    setError("");
    try {
      await rotateEvidenceKey(evidenceId);
      await loadAll();
    } catch (err) {
      setError(err.response?.data?.error || "Key rotation failed");
    } finally {
      setBusy("");
    }
  }

  function handleDownloadReport() {
    const url = downloadReportUrl(evidenceId, apiClient.defaults.baseURL);
    const token = localStorage.getItem("access_token");
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.blob())
      .then((blob) => {
        const link = document.createElement("a");
        link.href = window.URL.createObjectURL(blob);
        link.download = `forensic_report_${evidence.case_number}.pdf`;
        link.click();
      });
  }

  if (!evidence) {
    return <p className="text-sm text-slate-500">{error || "Loading..."}</p>;
  }

  return (
    <div>
      <Link to="/evidence" className="text-sm text-blue-600 hover:underline">&larr; Back to Evidence</Link>

      <div className="flex items-start justify-between mt-3 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">{evidence.title}</h1>
          <p className="text-sm text-slate-500">Case {evidence.case_number}</p>
        </div>
        <StatusBadge status={evidence.status} />
      </div>

      <Alert type="error">{error}</Alert>
      <Alert type="success">{downloadInfo}</Alert>
      {evidence.status === "tampered" && (
        <Alert type="warning">
          This evidence is flagged as COMPROMISED: it no longer matches its original SHA-256 hash.
          Downloads and previews are blocked while the stored copy fails the integrity check.
        </Alert>
      )}
      {showPreview && (
        <div className="mb-6">
          <FilePreview evidence={evidence} onClose={() => { setShowPreview(false); loadAll().catch(() => {}); }} onError={() => loadAll().catch(() => {})} />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left column: details + actions */}
        <div className="lg:col-span-1 space-y-4">
          <Section title="Details">
            <DetailRow label="Original file" value={evidence.original_filename} />
            <DetailRow label="Size" value={`${formatBytes(evidence.file_size_bytes)} (${evidence.file_size_bytes} bytes)`} />
            <DetailRow label="Type" value={evidence.mime_type || "-"} />
            <DetailRow label="Evidence ID" value={evidence.id} mono />
            <DetailRow label="Uploaded" value={new Date(evidence.created_at).toLocaleString()} />
            <DetailRow label="Last verified" value={evidence.last_verified_at ? new Date(evidence.last_verified_at).toLocaleString() : "Never"} />
            <DetailRow label="SHA-256" value={evidence.sha256_hash} mono />
            <DetailRow label="Storage backend" value={evidence.storage_backend === "s3" ? "Amazon S3 (private bucket, encrypted)" : "Local server storage"} />
            <DetailRow label="Peer nodes" value={evidence.replicated_nodes.join(", ")} />
          </Section>

          <Section title="Actions">
            <div className="space-y-2">
              {evidence.previewable && (
                <ActionButton onClick={() => setShowPreview(true)} label="View File" />
              )}
              <ActionButton onClick={handleDownload} busy={busy === "download"} label="Download File (integrity-checked)" />
              <ActionButton onClick={handleVerify} busy={busy === "verify"} label="Verify Integrity" variant="secondary" />
              <ActionButton onClick={handleSign} busy={busy === "sign"} label="Sign Evidence (RSA)" variant="secondary" />
              <ActionButton onClick={handleRotateKey} busy={busy === "rotate"} label="Rotate Encryption Key" variant="secondary" />
              <ActionButton onClick={handleDownloadReport} label="Download PDF Report" variant="secondary" />
            </div>
          </Section>

          {verifyResult && (
            <Section title="Last Verification Result">
              <VerifyResultCard result={verifyResult} />
            </Section>
          )}
        </div>

        {/* Right column: signatures + ledger */}
        <div className="lg:col-span-2 space-y-4">
          <Section title="Digital Signatures">
            {signatures.length === 0 ? (
              <p className="text-sm text-slate-500">No signatures yet.</p>
            ) : (
              <table className="w-full text-sm">
                <thead className="text-slate-500 text-left">
                  <tr>
                    <th className="py-1 font-medium">Signer</th>
                    <th className="py-1 font-medium">Signed At</th>
                    <th className="py-1 font-medium">Valid</th>
                  </tr>
                </thead>
                <tbody>
                  {signatures.map((sig) => (
                    <tr key={sig.id} className="border-t border-slate-100">
                      <td className="py-1.5 font-mono text-xs">{sig.signer_id.slice(0, 8)}...</td>
                      <td className="py-1.5 text-slate-500">{new Date(sig.created_at).toLocaleString()}</td>
                      <td className="py-1.5">
                        {sig.signature_valid ? (
                          <span className="text-green-600 font-medium">✓ Valid</span>
                        ) : (
                          <span className="text-red-600 font-medium">✗ Invalid</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          <Section title="Blockchain Ledger (Chain of Custody)">
            {ledger.length === 0 ? (
              <p className="text-sm text-slate-500">No ledger events yet.</p>
            ) : (
              <ol className="relative border-l border-slate-200 ml-2 space-y-4">
                {ledger.map((block) => (
                  <li key={block.block_id} className="ml-4">
                    <div className="absolute w-2.5 h-2.5 bg-blue-500 rounded-full -left-[5px] mt-1.5 border border-white" />
                    <p className="text-sm font-medium text-slate-800">{block.event_type}</p>
                    <p className="text-xs text-slate-500">{new Date(block.timestamp).toLocaleString()}</p>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">hash: {block.current_hash.slice(0, 20)}...</p>
                  </li>
                ))}
              </ol>
            )}
          </Section>
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4">
      <h2 className="text-sm font-semibold text-slate-700 mb-3">{title}</h2>
      {children}
    </div>
  );
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between gap-3 py-1 text-sm border-b border-slate-50 last:border-0">
      <span className="text-slate-500 shrink-0">{label}</span>
      <span className={`text-right text-slate-800 break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}

function ActionButton({ onClick, busy, label, variant = "primary" }) {
  const styles =
    variant === "primary"
      ? "bg-blue-600 hover:bg-blue-700 text-white"
      : "bg-slate-100 hover:bg-slate-200 text-slate-700";
  return (
    <button
      onClick={onClick}
      disabled={Boolean(busy)}
      className={`w-full text-sm font-medium rounded-lg py-2 transition-colors disabled:opacity-60 ${styles}`}
    >
      {busy ? "Working..." : label}
    </button>
  );
}

function VerifyResultCard({ result }) {
  return (
    <div className="space-y-2 text-sm">
      <div className={`font-medium ${result.hash_match ? "text-green-600" : "text-red-600"}`}>
        {result.hash_match ? "✓ Hash matches — evidence intact" : "✗ Hash mismatch — possible tampering"}
      </div>
      <DetailRow label="Ledger chain valid" value={result.ledger_chain.valid ? "Yes" : "No"} />
      <DetailRow label="Peer nodes consistent" value={result.peer_node_consistency.consistent === null ? "n/a (S3 storage)" : result.peer_node_consistency.consistent ? "Yes" : "No"} />
    </div>
  );
}
