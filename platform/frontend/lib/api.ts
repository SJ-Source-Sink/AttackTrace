import { getAccessToken, refreshAccessToken } from "@/lib/auth";
import type {
  OrgMember,
  ScheduledScan,
  ScheduledScanListResponse,
  CreateScheduleRequest,
  NotificationChannel,
  NotificationChannelListResponse,
  CreateChannelRequest,
} from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

interface FetchOptions extends RequestInit {
  skipAuth?: boolean;
  params?: Record<string, string | number | boolean | string[] | undefined>;
}

function buildUrl(path: string, params?: Record<string, string | number | boolean | string[] | undefined>): string {
  const url = new URL(`${API_BASE}${path}`);
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value === undefined || value === null) return;
      if (Array.isArray(value)) {
        value.forEach((v) => url.searchParams.append(key, String(v)));
      } else {
        url.searchParams.set(key, String(value));
      }
    });
  }
  return url.toString();
}

// Promise-based refresh: all concurrent 401s await the same promise so only
// one refresh request fires regardless of how many requests were in-flight.
let refreshPromise: Promise<string | null> | null = null;

export async function apiFetch<T>(
  path: string,
  options: FetchOptions = {},
): Promise<T> {
  const { skipAuth = false, params, ...fetchOptions } = options;

  const url = buildUrl(path, params);
  const headers = new Headers(fetchOptions.headers);

  if (!headers.has("Content-Type") && !(fetchOptions.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  if (!skipAuth) {
    const token = getAccessToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  let response = await fetch(url, {
    ...fetchOptions,
    headers,
  });

  // Handle 401 with token refresh — all concurrent callers share one refresh promise
  if (response.status === 401 && !skipAuth) {
    if (!refreshPromise) {
      refreshPromise = refreshAccessToken().finally(() => {
        refreshPromise = null;
      });
    }
    const newToken = await refreshPromise;

    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      response = await fetch(url, { ...fetchOptions, headers });
    } else {
      if (typeof window !== "undefined") {
        window.location.href = "/login";
      }
      throw new ApiError(401, "Session expired. Please login again.");
    }
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      const raw = errorData.detail ?? detail;
      detail = typeof raw === "string" ? raw : JSON.stringify(raw);
    } catch {
      // ignore
    }
    throw new ApiError(response.status, detail);
  }

  // Handle empty responses (204 No Content)
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

// Convenience methods
export const api = {
  get: <T>(path: string, params?: FetchOptions["params"]) =>
    apiFetch<T>(path, { method: "GET", params }),

  post: <T>(path: string, body?: unknown, options?: FetchOptions) =>
    apiFetch<T>(path, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
      ...options,
    }),

  patch: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, {
      method: "PATCH",
      body: body ? JSON.stringify(body) : undefined,
    }),

  put: <T>(path: string, body?: unknown) =>
    apiFetch<T>(path, {
      method: "PUT",
      body: body ? JSON.stringify(body) : undefined,
    }),

  delete: <T>(path: string) =>
    apiFetch<T>(path, { method: "DELETE" }),
};

// Specific API functions
export const authApi = {
  login: (email: string, password: string) =>
    api.post("/auth/login", { email, password }),
  register: (data: unknown) => api.post("/auth/register", data),
  me: () => api.get("/auth/me"),
};

export const scansApi = {
  list: (params?: Record<string, string | number | undefined>) =>
    api.get("/scans", params),
  get: (id: string) => api.get(`/scans/${id}`),
  create: (data: unknown) => api.post("/scans", data),
  cancel: (id: string) => api.delete(`/scans/${id}`),
  delete: (id: string) => api.delete(`/scans/${id}`),
  getDiff: (id: string) => api.get(`/scans/${id}/diff`),
};

export const assetsApi = {
  list: (params?: Record<string, string | number | string[] | undefined>) =>
    api.get("/assets", params),
  get: (id: string) => api.get(`/assets/${id}`),
  update: (id: string, data: unknown) => api.patch(`/assets/${id}`, data),
  bulkTag: (ids: string[], tags: unknown[]) =>
    api.post("/assets/bulk/tag", { ids, tags }),
  bulkAssign: (ids: string[], owner: string) =>
    api.post("/assets/bulk/assign", { ids, owner }),
  exportCsv: (params?: Record<string, string | undefined>) =>
    apiFetch<Blob>("/assets/export/csv", { method: "GET", params }),
};

export const findingsApi = {
  list: (params?: Record<string, string | number | string[] | undefined>) =>
    api.get("/findings", params),
  get: (id: string) => api.get(`/findings/${id}`),
  create: (data: unknown) => api.post("/findings", data),
  update: (id: string, data: unknown) => api.patch(`/findings/${id}`, data),
  addComment: (id: string, content: string) =>
    api.post(`/findings/${id}/comments`, { body: content }),
  timeline: (params: Record<string, string | number | undefined>) =>
    api.get("/findings/timeline", params),
};

export const reportsApi = {
  list: (scanId?: string) =>
    api.get("/reports", scanId ? { scan_job_id: scanId } : undefined),
  generate: (scanId: string, format: string = "html") =>
    api.post("/reports/generate", { scan_job_id: scanId, format }),
  /** Authenticated download — fetches with JWT then triggers browser save-as dialog */
  download: async (scanId: string, filename = `report_${scanId.slice(0, 8)}.html`): Promise<void> => {
    const token = getAccessToken();
    const res = await fetch(`${API_BASE}/reports/${scanId}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => `HTTP ${res.status}`);
      throw new ApiError(res.status, detail);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } finally {
      URL.revokeObjectURL(url);
    }
  },
  /** Authenticated PDF download — fetches with JWT then triggers browser save-as dialog */
  downloadPdf: async (scanId: string, filename = `report_${scanId.slice(0, 8)}.pdf`): Promise<void> => {
    const token = getAccessToken();
    const res = await fetch(`${API_BASE}/reports/${scanId}/pdf`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => `HTTP ${res.status}`);
      throw new ApiError(res.status, detail);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } finally {
      URL.revokeObjectURL(url);
    }
  },
  /** Return the PDF endpoint URL string */
  pdfUrl: (scanId: string): string => `${API_BASE}/reports/${scanId}/pdf`,
};

export const aiApi = {
  search: (query: string, context?: string) =>
    api.post("/ai/search", { query, context }),
  summarize: (scanId: string, includeRecommendations = true) =>
    api.post("/ai/summarize", {
      scan_id: scanId,
      include_recommendations: includeRecommendations,
    }),
};

export const dashboardApi = {
  stats: () => api.get("/dashboard/stats"),
  executive: () => api.get("/dashboard/executive"),
};

export const nucleiApi = {
  scan: (data: unknown) => api.post("/nuclei/scan", data),
  scans: () => api.get("/nuclei/scans"),
  getScan: (id: string) => api.get(`/nuclei/scans/${id}`),
  templates: (params?: { search?: string; severity?: string; category?: string; page?: number; per_page?: number }) =>
    api.get("/nuclei/templates", params),
  categories: () => api.get("/nuclei/templates/categories"),
  browseTemplates: (params?: { search?: string; category?: string; page?: number; per_page?: number }) =>
    api.get("/nuclei/templates/browse", params),
  toggleTemplate: (templateId: string, enabled: boolean) =>
    api.post(`/nuclei/templates/${encodeURIComponent(templateId)}/toggle`, { enabled }),
  uploadTemplate: async (file: File): Promise<{ filename: string; status: string }> => {
    const token = getAccessToken();
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${API_BASE}/nuclei/templates/upload`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => `HTTP ${res.status}`);
      throw new ApiError(res.status, detail);
    }
    return res.json();
  },
};

export const cloudApi = {
  discover: (provider: string, credentials: Record<string, string>) =>
    api.post("/cloud/discover", { provider, credentials }),
  listAssets: () => api.get("/cloud/assets"),
};

export const orgApi = {
  get: () => api.get("/org"),
  update: (data: unknown) => api.patch("/org", data),
  members: () => api.get("/org/members"),
  inviteMember: (email: string, role: string) =>
    api.post("/org/members/invite", { email, role }),
  removeMember: (userId: string) => api.delete(`/org/members/${userId}`),
  updateMemberRole: (userId: string, role: string) =>
    api.patch(`/org/members/${userId}`, { role }),
  apiKeys: () => api.get("/org/api-keys"),
  createApiKey: (data: unknown) => api.post("/org/api-keys", data),
  deleteApiKey: (id: string) => api.delete(`/org/api-keys/${id}`),
  getCredentials: () => api.get<Record<string, boolean>>("/org/credentials"),
  updateCredentials: (data: Record<string, string | null>) =>
    api.put<Record<string, boolean>>("/org/credentials", data),
  inviteCodes: () => api.get<{ items: InviteCodeItem[] }>("/org/invite-codes"),
  createInviteCode: (params: { role?: string; email?: string; expires_in_days?: number }) =>
    api.post<InviteCodeItem>("/org/invite-codes", undefined, {
      params: { role: params.role ?? "member", email: params.email, expires_in_days: params.expires_in_days ?? 7 },
    }),
  revokeInviteCode: (id: string) => api.delete(`/org/invite-codes/${id}`),
  getInviteLink: () => api.get<{ code: string; id: string }>("/org/invite-link"),
  regenerateInviteLink: () => api.post<{ code: string; id: string }>("/org/invite-link/regenerate"),
  createMember: (data: { full_name: string; email: string; password: string; role: string }) =>
    api.post<{ user_id: string; full_name: string; email: string; role: string; joined_at: string }>("/org/members/create", data),
  updateMemberPermissions: (userId: string, toolPermissions: string[] | null) =>
    api.patch<OrgMember>(`/org/members/${userId}/permissions`, { tool_permissions: toolPermissions }),
  updateSlaConfig: (orgId: string, config: Record<string, number>) =>
    api.patch(`/orgs/${orgId}/sla-config`, config),
};

export const schedulesApi = {
  list: (params?: { page?: number; per_page?: number }) =>
    apiFetch<ScheduledScanListResponse>("/schedules", { method: "GET", params }),
  get: (id: string) => apiFetch<ScheduledScan>(`/schedules/${id}`),
  create: (data: CreateScheduleRequest) =>
    apiFetch<ScheduledScan>("/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  update: (id: string, data: Partial<CreateScheduleRequest>) =>
    apiFetch<ScheduledScan>(`/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  delete: (id: string) => apiFetch<void>(`/schedules/${id}`, { method: "DELETE" }),
  trigger: (id: string) =>
    apiFetch<{ scan_job_id: string }>(`/schedules/${id}/trigger`, { method: "POST" }),
};

export const notificationsApi = {
  listChannels: () => apiFetch<NotificationChannelListResponse>("/notifications/channels"),
  createChannel: (data: CreateChannelRequest) =>
    apiFetch<NotificationChannel>("/notifications/channels", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateChannel: (id: string, data: Partial<CreateChannelRequest>) =>
    apiFetch<NotificationChannel>(`/notifications/channels/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteChannel: (id: string) =>
    apiFetch<void>(`/notifications/channels/${id}`, { method: "DELETE" }),
  testChannel: (id: string) =>
    apiFetch<{ success: boolean; message: string }>(
      `/notifications/channels/${id}/test`,
      { method: "POST" },
    ),
};

export interface InviteCodeItem {
  id: string;
  code: string;
  role: string;
  email?: string | null;
  is_valid: boolean;
  is_revoked: boolean;
  used_at?: string | null;
  expires_at?: string | null;
  created_at: string;
}
