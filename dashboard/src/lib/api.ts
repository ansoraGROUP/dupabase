const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3333";

interface ApiOptions {
  method?: string;
  body?: unknown;
  token?: string;
}

export async function api<T = unknown>(
  path: string,
  opts: ApiOptions = {}
): Promise<{ data: T | null; error: string | null }> {
  const { method = "GET", body, token } = opts;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json();
    if (!res.ok) {
      return { data: null, error: json.error || json.message || `Error ${res.status}` };
    }
    return { data: json as T, error: null };
  } catch (err) {
    return { data: null, error: (err as Error).message };
  }
}

// Platform Auth
export const platformAuth = {
  register: (email: string, password: string, inviteCode?: string) =>
    api<{ user: PlatformUser; token: string }>("/platform/auth/register", {
      method: "POST",
      body: { email, password, ...(inviteCode ? { invite_code: inviteCode } : {}) },
    }),
  login: (email: string, password: string) =>
    api<{ user: PlatformUser; token: string }>("/platform/auth/login", {
      method: "POST",
      body: { email, password },
    }),
  me: (token: string) =>
    api<PlatformUser>("/platform/auth/me", { token }),
  changePassword: (token: string, currentPassword: string, newPassword: string) =>
    api<{ message: string }>("/platform/auth/password", {
      method: "PUT",
      body: { current_password: currentPassword, new_password: newPassword },
      token,
    }),
};

// Projects
export const projects = {
  list: (token: string) =>
    api<Project[]>("/platform/projects", { token }),
  create: (token: string, name: string) =>
    api<Project>("/platform/projects", {
      method: "POST",
      body: { name },
      token,
    }),
  delete: (token: string, id: string) =>
    api<{ message: string }>(`/platform/projects/${id}`, {
      method: "DELETE",
      token,
    }),
  updateSettings: (token: string, id: string, settings: Partial<ProjectSettings>) =>
    api<ProjectSettings>(`/platform/projects/${id}/settings`, {
      method: "PATCH",
      body: settings,
      token,
    }),
};

// Credentials
export const credentials = {
  reveal: (token: string, password: string) =>
    api<{ pg_username: string; pg_password: string }>(
      "/platform/credentials/reveal",
      { method: "POST", body: { platform_password: password }, token }
    ),
};

// Import
export const imports = {
  start: async (
    token: string,
    projectId: string,
    file: File,
    options: ImportOptions = {}
  ): Promise<{ data: ImportTask | null; error: string | null }> => {
    const formData = new FormData();
    formData.append("file", file);
    if (options.clean_import) formData.append("clean_import", "true");
    formData.append("skip_auth_schema", options.skip_auth_schema === false ? "false" : "true");
    formData.append("disable_triggers", options.disable_triggers === false ? "false" : "true");
    try {
      const res = await fetch(
        `${API_URL}/platform/projects/${projectId}/import`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: formData,
        }
      );
      const json = await res.json();
      if (!res.ok) return { data: null, error: json.error || `Error ${res.status}` };
      return { data: json as ImportTask, error: null };
    } catch (err) {
      return { data: null, error: (err as Error).message };
    }
  },
  status: (token: string, projectId: string, taskId: number) =>
    api<ImportTask>(`/platform/projects/${projectId}/import/${taskId}`, { token }),
  history: (token: string, projectId: string) =>
    api<ImportTask[]>(`/platform/projects/${projectId}/import/history`, { token }),
  cancel: (token: string, projectId: string, taskId: number) =>
    api<{ status: string }>(`/platform/projects/${projectId}/import/${taskId}/cancel`, {
      method: "POST",
      token,
    }),
};

// Backups
export const backups = {
  getSettings: (token: string) =>
    api<BackupSettings>("/platform/backups/settings", { token }),
  saveSettings: (token: string, settings: SaveBackupSettingsRequest) =>
    api<BackupSettings>("/platform/backups/settings", {
      method: "POST",
      body: settings,
      token,
    }),
  getHistory: (token: string) =>
    api<BackupHistoryItem[]>("/platform/backups/history", { token }),
  runNow: (token: string) =>
    api<{ status: string }>("/platform/backups/run", {
      method: "POST",
      token,
    }),
};

// Registration mode (public, no auth)
export const registrationMode = {
  get: () => api<{ registration_mode: string }>("/platform/auth/registration-mode"),
};

// Admin
export const admin = {
  getUsers: (token: string, page = 1, perPage = 20) =>
    api<PaginatedUsers>(`/platform/admin/users?page=${page}&per_page=${perPage}`, { token }),
  deleteUser: (token: string, id: string) =>
    api<{ status: string }>(`/platform/admin/users/${id}`, {
      method: "DELETE",
      token,
    }),
  getSettings: (token: string) =>
    api<AdminPlatformSettings>("/platform/admin/settings", { token }),
  updateSettings: (token: string, settings: AdminPlatformSettings) =>
    api<{ status: string }>("/platform/admin/settings", {
      method: "PUT",
      body: settings,
      token,
    }),
  getInvites: (token: string) =>
    api<AdminInvite[]>("/platform/admin/invites", { token }),
  createInvite: (token: string, email?: string, expiresInHours?: number) =>
    api<AdminInvite>("/platform/admin/invites", {
      method: "POST",
      body: { email, expires_in_hours: expiresInHours },
      token,
    }),
  deleteInvite: (token: string, id: string) =>
    api<{ status: string }>(`/platform/admin/invites/${id}`, {
      method: "DELETE",
      token,
    }),
};

// Types
export interface SaveBackupSettingsRequest {
  s3_endpoint: string;
  s3_region: string;
  s3_bucket: string;
  s3_access_key: string;
  s3_secret_key: string;
  s3_path_prefix?: string;
  schedule?: string;
  retention_days?: number;
  project_ids?: string[];
  platform_password: string;
}

export interface BackupSettings {
  id: string;
  s3_endpoint: string;
  s3_region: string;
  s3_bucket: string;
  s3_path_prefix: string;
  schedule: string;
  retention_days: number;
  project_ids: string[];
  enabled: boolean;
}

export interface BackupHistoryItem {
  id: number;
  project_id: string;
  db_name: string;
  s3_key: string;
  size_bytes: number | null;
  status: "running" | "completed" | "failed";
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface ImportOptions {
  clean_import?: boolean;
  skip_auth_schema?: boolean;
  disable_triggers?: boolean;
}

export interface ImportTask {
  id: number;
  project_id: string;
  db_name: string;
  file_name: string;
  file_size: number;
  format: string;
  status: "uploading" | "running" | "completed" | "failed" | "cancelled";
  error_message: string | null;
  tables_imported: number | null;
  started_at: string;
  completed_at: string | null;
}

export interface PlatformUser {
  id: string;
  email: string;
  display_name?: string | null;
  pg_username: string;
  is_admin: boolean;
  created_at: string;
}

// Admin types
export interface AdminUser {
  id: string;
  email: string;
  display_name?: string | null;
  pg_username: string;
  is_admin: boolean;
  project_count: number;
  created_at: string;
}

export interface PaginatedUsers {
  users: AdminUser[];
  total: number;
  page: number;
  per_page: number;
}

export interface AdminPlatformSettings {
  registration_mode: "open" | "invite" | "disabled";
}

export interface AdminInvite {
  id: string;
  code: string;
  email: string | null;
  created_by: string;
  used_by: string | null;
  used_at: string | null;
  expires_at: string;
  created_at: string;
}

export interface ProjectSettings {
  enable_signup: boolean;
  autoconfirm: boolean;
  password_min_length: number;
}

export interface Project {
  id: string;
  name: string;
  db_name: string;
  anon_key: string;
  service_role_key: string;
  jwt_secret: string;
  site_url: string;
  settings: ProjectSettings;
  created_at: string;
}
