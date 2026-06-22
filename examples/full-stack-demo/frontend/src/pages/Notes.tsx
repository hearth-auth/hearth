import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useHasRole } from "@hearth-auth/sdk";
import UserMenu from "../components/UserMenu.js";
import RoleGate from "../components/RoleGate.js";
import { api, type Note } from "../api.js";

export default function Notes() {
  const isAdmin = useHasRole("admin");
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api
      .getNotes()
      .then(setNotes)
      .catch((err: unknown) =>
        setError(
          err instanceof Error
            ? err.message
            : "Backend not running — start Phase 3 (cd backend && cargo run)",
        ),
      )
      .finally(() => setLoading(false));
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;
    setSaving(true);
    try {
      const note = await api.createNote({ title, content });
      setNotes((prev) => [note, ...prev]);
      setTitle("");
      setContent("");
      setShowForm(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <nav className="nav">
          <span className="nav-brand">Hearth Hub</span>
          <div className="nav-links">
            <Link to="/dashboard" className="nav-link">Dashboard</Link>
            <Link to="/notes" className="nav-link active">Notes</Link>
            {isAdmin && <Link to="/admin" className="nav-link">Admin</Link>}
          </div>
          <UserMenu />
        </nav>
      </header>

      <main className="page-content">
        <div className="page-title-row">
          <h2>Notes</h2>
          {/* "New Note" is only visible to editors and admins. */}
          <RoleGate
            permission="content.write"
            fallback={
              <span className="hint">
                You have read-only access.
              </span>
            }
          >
            <button
              className="btn btn-primary"
              onClick={() => setShowForm((v) => !v)}
            >
              {showForm ? "Cancel" : "New Note"}
            </button>
          </RoleGate>
        </div>

        {showForm && (
          <form className="card form-card" onSubmit={(e) => void handleCreate(e)}>
            <h3>New note</h3>
            <label>
              Title
              <input
                className="input"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
              />
            </label>
            <label>
              Content
              <textarea
                className="input"
                rows={4}
                value={content}
                onChange={(e) => setContent(e.target.value)}
              />
            </label>
            <button className="btn btn-primary" type="submit" disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          </form>
        )}

        {error && (
          <div className="alert alert-error">
            <strong>Could not load notes</strong>
            <p>{error}</p>
          </div>
        )}

        {loading && (
          <div className="loading-inline">
            <span className="spinner" /> Loading…
          </div>
        )}

        {!loading && !error && notes.length === 0 && (
          <div className="empty-state">No notes yet.</div>
        )}

        <ul className="note-list">
          {notes.map((note) => (
            <li key={note.id} className="card note-card">
              <h4>{note.title}</h4>
              <p>{note.content}</p>
              <footer className="note-meta">
                {note.author} · {new Date(note.created_at).toLocaleString()}
              </footer>
            </li>
          ))}
        </ul>
      </main>
    </div>
  );
}
