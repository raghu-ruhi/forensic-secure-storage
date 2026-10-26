import { useEffect, useState } from "react";
import { loadPreview } from "../utils/files";
import { errorMessage } from "../utils/files";

/**
 * Safe, read-only preview of an evidence file. Only images, PDFs and plain
 * text are ever rendered; everything else is download-only. Text is shown
 * through React (escaped), images via <img>, and PDFs via the browser's PDF
 * viewer from a blob of the verified type - uploaded content is never
 * injected as HTML.
 */
export default function FilePreview({ evidence, onClose, onError }) {
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    let url = null;
    let cancelled = false;
    loadPreview(evidence)
      .then((p) => {
        if (cancelled) {
          if (p.url) window.URL.revokeObjectURL(p.url);
          return;
        }
        url = p.url || null;
        setState({ loading: false, ...p });
      })
      .catch(async (err) => {
        const msg = err.response ? await errorMessage(err, "Preview failed.") : err.message;
        if (!cancelled) {
          setState({ loading: false, failed: msg });
          onError?.(msg);
        }
      });
    return () => {
      cancelled = true;
      if (url) window.URL.revokeObjectURL(url);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidence.id]);

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-700">Preview — {evidence.original_filename}</h2>
        <button onClick={onClose} className="text-sm text-slate-500 hover:text-slate-800">Close ✕</button>
      </div>
      {state.loading && <p className="text-sm text-slate-500">Verifying integrity and decrypting...</p>}
      {state.failed && <p className="text-sm text-red-600">{state.failed}</p>}
      {state.type === "image" && (
        <img src={state.url} alt={evidence.original_filename} className="max-w-full max-h-[70vh] mx-auto rounded" />
      )}
      {state.type === "pdf" && (
        <iframe title="PDF preview" src={state.url} className="w-full h-[70vh] rounded border border-slate-200" />
      )}
      {state.type === "text" && (
        <>
          <pre className="text-xs bg-slate-50 border border-slate-200 rounded p-3 overflow-auto max-h-[70vh] whitespace-pre-wrap break-all">
            {state.text}
          </pre>
          {state.truncated && <p className="text-xs text-slate-500 mt-2">Showing the first 200,000 characters. Download for the full file.</p>}
        </>
      )}
    </div>
  );
}
