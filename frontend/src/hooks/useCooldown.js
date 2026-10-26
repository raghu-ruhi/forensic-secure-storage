import { useCallback, useEffect, useState } from "react";

/** Seconds-remaining countdown for "Resend code" buttons. */
export default function useCooldown(initial = 0) {
  const [seconds, setSeconds] = useState(initial);
  useEffect(() => {
    if (seconds <= 0) return undefined;
    const id = setTimeout(() => setSeconds((s) => s - 1), 1000);
    return () => clearTimeout(id);
  }, [seconds]);
  const start = useCallback((n) => setSeconds(Math.max(0, Math.ceil(n || 0))), []);
  return [seconds, start];
}
