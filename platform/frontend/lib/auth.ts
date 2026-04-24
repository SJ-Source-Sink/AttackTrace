"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import type { User, LoginRequest, RegisterRequest, AuthResponse } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";
const REFRESH_TOKEN_KEY = "attacktrace_rt";
const ACCESS_TOKEN_KEY = "attacktrace_at";

// Access token stored in both sessionStorage (primary) and localStorage (fallback).
// sessionStorage is cleared when the tab closes; localStorage persists but is also
// cleared on explicit logout to avoid stale tokens.
export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(ACCESS_TOKEN_KEY) || localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function setAccessToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, token);
    localStorage.setItem(ACCESS_TOKEN_KEY, token);
  } else {
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(ACCESS_TOKEN_KEY);
  }
}

function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

function setRefreshToken(token: string | null): void {
  if (typeof window === "undefined") return;
  if (token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }
}

// Inflight dedup lock: concurrent 401s only trigger a single refresh request.
let _refreshInFlight: Promise<string | null> | null = null;

export async function refreshAccessToken(): Promise<string | null> {
  if (_refreshInFlight) return _refreshInFlight;
  _refreshInFlight = _doRefresh().finally(() => {
    _refreshInFlight = null;
  });
  return _refreshInFlight;
}

async function _doRefresh(): Promise<string | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return null;

  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      setRefreshToken(null);
      setAccessToken(null);
      return null;
    }

    const data: AuthResponse = await response.json();
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    return data.access_token;
  } catch {
    return null;
  }
}

/**
 * Drop-in fetch wrapper that automatically refreshes the access token on 401
 * and retries the request once. Falls back to the original 401 response if
 * the refresh also fails (user needs to log in again).
 */
export async function fetchWithAuth(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  const token = getAccessToken();
  const withAuth = (t: string | null): RequestInit => ({
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      ...(t ? { Authorization: `Bearer ${t}` } : {}),
    },
  });

  const resp = await fetch(input, withAuth(token));
  if (resp.status !== 401) return resp;

  // Try refreshing the token once
  const newToken = await refreshAccessToken();
  if (!newToken) return resp; // refresh failed — caller handles 401

  return fetch(input, withAuth(newToken));
}

// ============================================================
// Auth Context
// ============================================================

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchCurrentUser = useCallback(async (token: string): Promise<User | null> => {
    try {
      const response = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) return null;
      return response.json();
    } catch {
      return null;
    }
  }, []);

  // On mount: restore session — use existing access token if still valid, else refresh
  useEffect(() => {
    const init = async () => {
      // Try existing access token first (survives route navigations via sessionStorage)
      const existingToken = getAccessToken();
      if (existingToken) {
        const userData = await fetchCurrentUser(existingToken);
        if (userData) {
          setUser(userData);
          setIsLoading(false);
          return;
        }
        // Token expired — fall through to refresh
        setAccessToken(null);
      }

      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        setIsLoading(false);
        return;
      }

      const token = await refreshAccessToken();
      if (token) {
        const userData = await fetchCurrentUser(token);
        setUser(userData);
      }
      setIsLoading(false);
    };

    init();
  }, [fetchCurrentUser]);

  const login = useCallback(async (credentials: LoginRequest) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error?.detail?.error?.message ?? error?.detail ?? "Login failed");
    }

    const data: AuthResponse = await response.json();
    setAccessToken(data.access_token);
    setRefreshToken(data.refresh_token);
    const userData = await fetchCurrentUser(data.access_token);
    setUser(userData);
  }, [fetchCurrentUser]);

  const register = useCallback(async (data: RegisterRequest) => {
    const response = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error?.detail?.error?.message ?? error?.detail ?? "Registration failed");
    }

    const authData: AuthResponse = await response.json();
    setAccessToken(authData.access_token);
    setRefreshToken(authData.refresh_token);
    const userData = await fetchCurrentUser(authData.access_token);
    setUser(userData);
  }, [fetchCurrentUser]);

  const logout = useCallback(() => {
    setAccessToken(null);
    setRefreshToken(null);
    setUser(null);
  }, []);

  const value: AuthContextValue = {
    user,
    isLoading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
  };

  return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
