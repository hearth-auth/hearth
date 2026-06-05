// Typed fetch wrapper that auto-attaches Authorization: Bearer <token>.

import { getAccessToken } from "@hearth/sdk";

const API_BASE = (import.meta.env.VITE_API_URL as string) ?? "http://localhost:8421";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAccessToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!resp.ok) {
    throw new Error(`API ${resp.status} ${resp.statusText} — ${path}`);
  }
  return resp.json() as Promise<T>;
}

export interface Note {
  id: string;
  title: string;
  content: string;
  author: string;
  created_at: string;
}

export interface ApiUser {
  id: string;
  email: string;
  display_name: string;
  roles: string[];
}

export const api = {
  getNotes: () => apiFetch<Note[]>("/api/notes"),

  createNote: (note: { title: string; content: string }) =>
    apiFetch<Note>("/api/notes", {
      method: "POST",
      body: JSON.stringify(note),
    }),

  /** Admin-only: list all users in the demo realm. */
  getUsers: () => apiFetch<ApiUser[]>("/admin/users"),
};
