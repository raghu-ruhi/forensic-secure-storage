const statusStyles = {
  stored: "bg-slate-100 text-slate-700",
  verified: "bg-green-100 text-green-700",
  tampered: "bg-red-100 text-red-700",
};

export default function StatusBadge({ status }) {
  const style = statusStyles[status] || "bg-slate-100 text-slate-700";
  return (
    <span className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-medium uppercase tracking-wide ${style}`}>
      {status}
    </span>
  );
}
