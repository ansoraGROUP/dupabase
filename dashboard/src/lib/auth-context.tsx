"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { platformAuth, type PlatformUser } from "./api";

interface AuthState {
  user: PlatformUser | null;
  token: string | null;
  loading: boolean;
}

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<string | null>;
  register: (email: string, password: string, inviteCode?: string) => Promise<string | null>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    token: null,
    loading: true,
  });

  const loadUser = useCallback(async (token: string) => {
    const { data, error } = await platformAuth.me(token);
    if (error || !data) {
      localStorage.removeItem("platform_token");
      setState({ user: null, token: null, loading: false });
      return;
    }
    setState({ user: data, token, loading: false });
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("platform_token");
    if (token) {
      loadUser(token);
    } else {
      setState((s) => ({ ...s, loading: false }));
    }
  }, [loadUser]);

  const login = async (email: string, password: string) => {
    const { data, error } = await platformAuth.login(email, password);
    if (error || !data) return error || "Login failed";
    localStorage.setItem("platform_token", data.token);
    setState({ user: data.user, token: data.token, loading: false });
    return null;
  };

  const register = async (email: string, password: string, inviteCode?: string) => {
    const { data, error } = await platformAuth.register(email, password, inviteCode);
    if (error || !data) return error || "Registration failed";
    localStorage.setItem("platform_token", data.token);
    setState({ user: data.user, token: data.token, loading: false });
    return null;
  };

  const logout = () => {
    localStorage.removeItem("platform_token");
    setState({ user: null, token: null, loading: false });
  };

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
