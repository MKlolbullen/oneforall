import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, Eye, EyeOff, KeyRound, Lock, Plus, ShieldCheck, Trash2, UserPlus, Users as UsersIcon, X } from 'lucide-react';
import { api } from './api';
import { CopyButton } from './CopyButton';
import { EmptyState } from './EmptyState';
import { useToast } from './Toast';
import { useConfirm } from './Confirm';
import type { APIKeyPublic, CreatedAPIKey, UserPublic, WhoAmI } from '../types';

function relTime(iso?: string | null): string {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.floor(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

function roleBadgeClass(role: string) {
  if (role === 'admin') return 'badge bad';
  if (role === 'operator') return 'badge active';
  return 'badge passive';
}

export function Users() {
  const toast = useToast();
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [users, setUsers] = useState<UserPublic[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Add-user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'viewer' | 'operator' | 'admin'>('viewer');
  const [showPw, setShowPw] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);

  const isAdmin = me?.role === 'admin';

  const reload = async () => {
    try {
      const who = await api.me();
      setMe(who);
      if (who.role === 'admin') {
        setUsers(await api.listUsers());
      } else {
        setUsers([]);
      }
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const createUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || newPassword.length < 8) {
      toast.warn('Invalid form', 'Username required + password ≥ 8 characters.');
      return;
    }
    setCreatingUser(true);
    try {
      await api.createUser({
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      });
      toast.success('User created', `${newUsername} as ${newRole}.`);
      setNewUsername('');
      setNewPassword('');
      setNewRole('viewer');
      reload();
    } catch (err) {
      toast.fromError(err, 'Create user failed');
    } finally {
      setCreatingUser(false);
    }
  };

  const changeRole = async (u: UserPublic, role: string) => {
    try {
      await api.updateUser(u.id, { role });
      toast.success('Role updated', `${u.username} → ${role}`);
      reload();
    } catch (err) {
      toast.fromError(err, 'Update failed');
    }
  };

  const toggleActive = async (u: UserPublic) => {
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      toast.success(u.is_active ? 'Deactivated' : 'Reactivated', u.username);
      reload();
    } catch (err) {
      toast.fromError(err, 'Update failed');
    }
  };

  if (error && !me) {
    return (
      <div className="card">
        <div className="row space"><h3>Users</h3></div>
        <p className="advice-error">{error}</p>
      </div>
    );
  }

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><UsersIcon size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Users & API keys</h3>
          <span className="muted">
            Local accounts (PBKDF2-hashed) + per-user bearer tokens. Admins can mint and demote;
            everyone can manage their own API keys.
          </span>
        </div>
      </div>

      {/* Admin-only roster + create form */}
      {isAdmin ? (
        <>
          <form className="card" onSubmit={createUser}>
            <div className="row space"><strong><UserPlus size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />Add user</strong></div>
            <div className="grid cols-3" style={{ alignItems: 'end' }}>
              <input
                className="input"
                placeholder="Username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                required maxLength={120}
              />
              <div className="row" style={{ position: 'relative' }}>
                <input
                  className="input"
                  type={showPw ? 'text' : 'password'}
                  placeholder="Password (≥8 chars)"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required minLength={8} maxLength={512}
                />
                <button
                  type="button"
                  className="icon-btn"
                  style={{ position: 'absolute', right: 6 }}
                  onClick={() => setShowPw((v) => !v)}
                  title={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
              <select className="input" value={newRole}
                      onChange={(e) => setNewRole(e.target.value as 'viewer' | 'operator' | 'admin')}>
                <option value="viewer">viewer · read-only</option>
                <option value="operator">operator · create + run</option>
                <option value="admin">admin · manage users + keys</option>
              </select>
            </div>
            <div className="row space" style={{ marginTop: 8 }}>
              <span className="muted small">Password is hashed with PBKDF2-HMAC-SHA256 + 16-byte salt before storage.</span>
              <button className="btn" type="submit" disabled={creatingUser || !newUsername.trim() || newPassword.length < 8}>
                <Plus size={14} /> {creatingUser ? 'Creating…' : 'Create user'}
              </button>
            </div>
          </form>

          <div className="card">
            <div className="row space">
              <strong>Roster</strong>
              <span className="muted">{users.length} user{users.length === 1 ? '' : 's'}</span>
            </div>
            {users.length === 0 ? (
              <p className="muted">No users yet.</p>
            ) : (
              <table className="table">
                <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th>Created</th><th /></tr></thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <strong>{u.username}</strong>
                        {me?.id === u.id && <span className="badge passive" style={{ marginLeft: 6 }}>you</span>}
                        <br /><span className="muted mono small">{u.id}</span>
                      </td>
                      <td>
                        <select
                          className="input"
                          style={{ padding: '4px 6px', maxWidth: 130 }}
                          value={u.role}
                          onChange={(e) => changeRole(u, e.target.value)}
                          disabled={me?.id === u.id}
                          title={me?.id === u.id ? 'Cannot demote yourself' : 'Change role'}
                        >
                          <option value="viewer">viewer</option>
                          <option value="operator">operator</option>
                          <option value="admin">admin</option>
                        </select>
                      </td>
                      <td>
                        <span className={u.is_active ? 'badge ok' : 'badge bad'}>
                          {u.is_active ? 'active' : 'disabled'}
                        </span>
                      </td>
                      <td className="muted small">{relTime(u.last_login_at)}</td>
                      <td className="muted small" title={u.created_at}>{relTime(u.created_at)}</td>
                      <td>
                        <button
                          className="btn small"
                          onClick={() => toggleActive(u)}
                          disabled={me?.id === u.id}
                          title={me?.id === u.id ? 'Cannot deactivate yourself' : (u.is_active ? 'Deactivate this user' : 'Reactivate this user')}
                        >
                          {u.is_active ? 'Deactivate' : 'Reactivate'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      ) : (
        <div className="card admin-only-card">
          <div className="row">
            <Lock size={14} color="#94a3b8" />
            <span className="muted">User management is admin-only. {me ? `Signed in as ${me.role}.` : ''}</span>
          </div>
        </div>
      )}

      <MyApiKeys me={me} />
    </div>
  );
}

/* ============================================================================
 * Own API keys — list + create (one-shot reveal) + revoke
 * ========================================================================== */

function MyApiKeys({ me }: { me: WhoAmI | null }) {
  const toast = useToast();
  const confirm = useConfirm();
  const [keys, setKeys] = useState<APIKeyPublic[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  // The newly-issued token is shown ONCE: the API never returns it again.
  // Stash it here so the operator can copy it; clear on dismiss.
  const [justCreated, setJustCreated] = useState<CreatedAPIKey | null>(null);

  const reload = async () => {
    try {
      setKeys(await api.listApiKeys());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    try {
      const issued = await api.createApiKey(name.trim());
      setJustCreated(issued);
      setName('');
      reload();
    } catch (err) {
      toast.fromError(err, 'Create key failed');
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (k: APIKeyPublic) => {
    const ok = await confirm({
      title: `Revoke API key "${k.name}"?`,
      body: `This key (${k.prefix}…) will stop working immediately. Anything using it will start receiving 401s.`,
      confirmLabel: 'Revoke',
      cancelLabel: 'Keep',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.revokeApiKey(k.id);
      toast.success('Key revoked', k.name);
      reload();
    } catch (err) {
      toast.fromError(err, 'Revoke failed');
    }
  };

  const active = useMemo(() => keys.filter((k) => !k.revoked_at), [keys]);
  const revoked = useMemo(() => keys.filter((k) => k.revoked_at), [keys]);

  return (
    <div className="card">
      <div className="row space">
        <strong><KeyRound size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Your API keys</strong>
        <span className="muted">{me ? `Signed in as ${me.username} (${me.role})` : '—'}</span>
      </div>

      <form className="row" style={{ marginTop: 6, gap: 8 }} onSubmit={create}>
        <input
          className="input"
          style={{ maxWidth: 280 }}
          placeholder="Key name (e.g. ci-runner, laptop)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required maxLength={120}
        />
        <button className="btn small" type="submit" disabled={creating || !name.trim()}>
          <Plus size={13} /> {creating ? 'Issuing…' : 'Issue key'}
        </button>
      </form>

      {justCreated && (
        <NewKeyReveal token={justCreated.token} prefix={justCreated.prefix}
                       onDismiss={() => setJustCreated(null)} />
      )}

      {error && <p className="advice-error" style={{ marginTop: 8 }}>{error}</p>}

      {keys.length === 0 && !error ? (
        <EmptyState
          icon={<KeyRound size={20} />}
          title="No API keys yet"
          body="Issue one above to use the API non-interactively (CI, scripts, the agent integration)."
        />
      ) : (
        <>
          {active.length > 0 && (
            <table className="table compact" style={{ marginTop: 10 }}>
              <thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th>Created</th><th /></tr></thead>
              <tbody>
                {active.map((k) => (
                  <tr key={k.id}>
                    <td><strong>{k.name}</strong></td>
                    <td><span className="mono small">{k.prefix}…</span></td>
                    <td className="muted small">{relTime(k.last_used_at)}</td>
                    <td className="muted small">{relTime(k.created_at)}</td>
                    <td>
                      <button className="btn small danger" onClick={() => revoke(k)} type="button">
                        <Trash2 size={12} /> Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {revoked.length > 0 && (
            <details style={{ marginTop: 12 }}>
              <summary className="muted">Revoked ({revoked.length})</summary>
              <table className="table compact">
                <thead><tr><th>Name</th><th>Prefix</th><th>Revoked</th></tr></thead>
                <tbody>
                  {revoked.map((k) => (
                    <tr key={k.id}>
                      <td>{k.name}</td>
                      <td><span className="mono small">{k.prefix}…</span></td>
                      <td className="muted small">{relTime(k.revoked_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </>
      )}
    </div>
  );
}

function NewKeyReveal({ token, prefix, onDismiss }: { token: string; prefix: string; onDismiss: () => void }) {
  return (
    <div className="key-reveal">
      <div className="row space">
        <strong><ShieldCheck size={14} /> Key issued (one-time reveal)</strong>
        <button className="icon-btn" onClick={onDismiss} type="button" aria-label="Dismiss"><X size={12} /></button>
      </div>
      <p className="muted small">
        Copy this now — only its sha256 + prefix (<span className="mono">{prefix}</span>) are stored.
        You won't be able to view this token again.
      </p>
      <div className="key-reveal-box">
        <code className="mono">{token}</code>
        <CopyButton value={token} title="Copy token" />
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <CheckCircle2 size={12} color="#22c55e" />
        <span className="muted small">Use as <code>Authorization: Bearer &lt;token&gt;</code> on every /api/* request.</span>
      </div>
    </div>
  );
}
