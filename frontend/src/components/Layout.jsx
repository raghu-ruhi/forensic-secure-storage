import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: "📊" },
  { to: "/evidence/upload", label: "Upload Evidence", icon: "⬆️" },
  { to: "/evidence", label: "Evidence", icon: "🗂️" },
  { to: "/keys", label: "Keys", icon: "🔑" },
  { to: "/audit-logs", label: "Audit Logs", icon: "📜", adminOnly: true },
  { to: "/invigilators", label: "Invigilators", icon: "🧑‍💼", adminOnly: true },
  { to: "/peer-storage", label: "Peer Storage", icon: "🌐" },
  { to: "/mfa-setup", label: "MFA Setup", icon: "🛡️" },
  { to: "/settings", label: "Settings", icon: "⚙️" },
];

export default function Layout() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="flex min-h-screen bg-slate-50">
      <aside className="w-64 bg-slate-900 text-slate-100 flex flex-col shrink-0">
        <div className="px-6 py-5 border-b border-slate-700">
          <h1 className="text-lg font-bold leading-tight">Forensic Secure Storage</h1>
          <p className="text-xs text-slate-400 mt-1">DFA-AOKGE Demo Platform</p>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems
            .filter((item) => !item.adminOnly || isAdmin)
            .map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                    isActive
                      ? "bg-blue-600 text-white"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white"
                  }`
                }
              >
                <span>{item.icon}</span>
                {item.label}
              </NavLink>
            ))}
        </nav>
        <div className="px-4 py-4 border-t border-slate-700">
          <p className="text-sm font-medium truncate">{user?.full_name}</p>
          <p className="text-xs text-slate-400 truncate">{user?.email}</p>
          <span className="inline-block mt-2 text-[10px] uppercase tracking-wide bg-slate-700 text-slate-200 px-2 py-0.5 rounded">
            {user?.role}
          </span>
          <button
            onClick={handleLogout}
            className="mt-3 w-full text-sm bg-red-600/90 hover:bg-red-600 text-white rounded-lg py-1.5 transition-colors"
          >
            Log out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-6xl mx-auto p-6 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
