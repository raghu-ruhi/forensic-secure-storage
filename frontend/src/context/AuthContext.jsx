import apiClient from "../api/client";
import { createContext, useContext, useState, useCallback } from "react";
import { fetchMe } from "../api/endpoints";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem("user");
    return stored ? JSON.parse(stored) : null;
  });
  const [loading, setLoading] = useState(false);

  const login = useCallback((token, userData) => {
    localStorage.setItem("access_token", token);
    localStorage.setItem("user", JSON.stringify(userData));
    setUser(userData);
  }, []);

  const logout = useCallback(() => {
    // Revoke the token server-side (best effort), then clear local state.
    apiClient.post("/auth/logout").catch(() => {});
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");
    setUser(null);
  }, []);

  const refreshUser = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchMe();
      localStorage.setItem("user", JSON.stringify(res.data));
      setUser(res.data);
    } finally {
      setLoading(false);
    }
  }, []);

  const isAuthenticated = Boolean(user && localStorage.getItem("access_token"));
  const isAdmin = user?.role === "admin";

  return (
    <AuthContext.Provider value={{ user, login, logout, refreshUser, isAuthenticated, isAdmin, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
