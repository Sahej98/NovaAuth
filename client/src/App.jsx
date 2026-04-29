import { useEffect, useState } from 'react';
import {
  BrowserRouter,
  Link,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useSearchParams,
} from 'react-router-dom';
import './App.css';

const defaultRegisterForm = {
  displayName: '',
  desiredHandle: '',
  password: '',
};

const defaultLoginForm = {
  login: '',
  password: '',
};

const defaultHandleStatus = {
  state: 'idle',
  message: 'Choose your NovaAuth handle.',
  suggestion: '',
  novaAuthId: '',
};

function defaultAppForm(settings) {
  return {
    clientName: '',
    description: '',
    applicationUrl: '',
    redirectUris: '',
    allowedOrigins: '',
    clientType: settings?.developerDefaultClientType || 'public',
    allowedScopes: settings?.developerDefaultScopes || ['openid', 'profile', 'email'],
    defaultScopes: settings?.developerDefaultScopes || ['openid', 'profile', 'email'],
    logoText: '',
    status: 'active',
  };
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.error || 'Request failed.');
  }

  return payload;
}

function getNextPath(searchParams, fallback = '/dashboard') {
  const next = searchParams.get('next');
  return next && next.startsWith('/') ? next : fallback;
}

function joinLines(values) {
  return Array.isArray(values) ? values.join('\n') : '';
}

function startPageToPath(startPage) {
  if (startPage === 'apps') {
    return '/apps';
  }
  if (startPage === 'settings') {
    return '/settings';
  }
  if (startPage === 'docs') {
    return '/docs';
  }
  return '/dashboard';
}

function useDocumentTheme(themePreference) {
  useEffect(() => {
    document.documentElement.dataset.theme = themePreference || 'system';
    document.documentElement.style.colorScheme =
      themePreference && themePreference !== 'system' ? themePreference : 'light dark';
  }, [themePreference]);
}

function ProtectedRoute({ session, children }) {
  const location = useLocation();

  if (!session?.authenticated) {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/auth?next=${encodeURIComponent(next)}`} replace />;
  }

  return children;
}

function AppShell() {
  const [session, setSession] = useState(null);
  const [oauthInfo, setOauthInfo] = useState(null);
  const [booting, setBooting] = useState(true);
  const themePreference = session?.user?.settings?.themePreference || 'system';
  useDocumentTheme(themePreference);

  useEffect(() => {
    Promise.all([
      apiRequest('/api/auth/session').catch(() => null),
      apiRequest('/api/sso/apps').catch(() => null),
    ])
      .then(([sessionPayload, oauthPayload]) => {
        setSession(sessionPayload?.authenticated ? sessionPayload : null);
        setOauthInfo(oauthPayload);
      })
      .finally(() => {
        setBooting(false);
      });
  }, []);

  async function refreshSession() {
    const payload = await apiRequest('/api/auth/session');
    setSession(payload.authenticated ? payload : null);
    return payload;
  }

  function applyUserUpdate(user) {
    setSession((current) => {
      if (!current) {
        return current;
      }

      return {
        ...current,
        user,
      };
    });
  }

  async function handleLogout() {
    await apiRequest('/api/auth/logout', { method: 'POST' });
    setSession(null);
  }

  if (booting) {
    return (
      <div className="screen-center">
        <div className="loading-card">
          <span className="eyebrow">NovaAuth</span>
          <h1>Loading workspace</h1>
          <p>Preparing your identity cloud and developer console.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" to="/">
          <span className="brand-mark">N</span>
          <span>
            <strong>NovaAuth</strong>
            <small>Identity for your apps</small>
          </span>
        </Link>

        <nav className="topnav">
          <NavLink to="/">Home</NavLink>
          <NavLink to="/docs">Docs</NavLink>
          {session?.authenticated ? <NavLink to="/dashboard">Dashboard</NavLink> : null}
          {session?.authenticated ? <NavLink to="/apps">Apps</NavLink> : null}
          {session?.authenticated ? <NavLink to="/settings">Settings</NavLink> : null}
        </nav>

        <div className="topbar-actions">
          {session?.authenticated ? (
            <>
              <Link className="ghost-button" to="/dashboard">
                {session.user.handle}
                {session.inbox?.unreadCount ? ` · ${session.inbox.unreadCount}` : ''}
              </Link>
              <button className="primary-button" onClick={handleLogout} type="button">
                Sign out
              </button>
            </>
          ) : (
            <Link className="primary-button" to="/auth">
              Sign in
            </Link>
          )}
        </div>
      </header>

      <main className="page-shell">
        <Routes>
          <Route path="/" element={<LandingPage oauthInfo={oauthInfo} session={session} />} />
          <Route
            path="/auth"
            element={<AuthPage refreshSession={refreshSession} session={session} />}
          />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute session={session}>
                <DashboardPage refreshSession={refreshSession} session={session} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/apps"
            element={
              <ProtectedRoute session={session}>
                <AppsPage oauthInfo={oauthInfo} session={session} />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute session={session}>
                <SettingsPage
                  applyUserUpdate={applyUserUpdate}
                  refreshSession={refreshSession}
                  session={session}
                />
              </ProtectedRoute>
            }
          />
          <Route path="/docs" element={<DocsPage oauthInfo={oauthInfo} session={session} />} />
          <Route
            path="/authorize"
            element={<AuthorizePage refreshSession={refreshSession} session={session} />}
          />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
    </div>
  );
}

function LandingPage({ oauthInfo, session }) {
  return (
    <div className="page-grid">
      <section className="hero-card">
        <div className="hero-copy">
          <span className="eyebrow">OAuth2 + OpenID Connect</span>
          <h1>Sign in with NovaAuth for every app you build.</h1>
          <p className="lead">
            NovaAuth is now a real backend-driven identity provider with developer app registration,
            consent screens, persistent settings, and reusable OAuth2 endpoints.
          </p>
          <div className="button-row">
            <Link className="primary-button" to={session?.authenticated ? '/apps' : '/auth'}>
              {session?.authenticated ? 'Open developer console' : 'Create your identity'}
            </Link>
            <Link className="ghost-button" to="/docs">
              Read integration docs
            </Link>
          </div>
        </div>

        <div className="stack">
          <article className="info-card accent">
            <span className="card-label">Issuer</span>
            <strong>{oauthInfo?.issuer || 'http://localhost:4000'}</strong>
            <p>Use Authorization Code + PKCE for browser apps and confidential clients for servers.</p>
          </article>
          <article className="info-card">
            <span className="card-label">Built-in flows</span>
            <p>Authorize, token exchange, refresh, userinfo, introspection, revocation, and JWKS discovery.</p>
          </article>
          <article className="info-card">
            <span className="card-label">Product surface</span>
            <p>Multipage experience with dashboard, settings, app management, docs, and consent pages.</p>
          </article>
        </div>
      </section>

      <section className="content-grid">
        <article className="panel">
          <h2>Why this feels real now</h2>
          <div className="feature-list">
            <div>
              <strong>Persistent account settings</strong>
              <p>Theme preference, layout mode, start page, notifications, and developer defaults are stored on the backend.</p>
            </div>
            <div>
              <strong>Self-serve OAuth apps</strong>
              <p>Register your own client IDs, redirect URIs, scopes, public or confidential mode, and rotate secrets.</p>
            </div>
            <div>
              <strong>Developer-ready docs</strong>
              <p>Copy the authorize URL pattern, token exchange steps, and a NovaAuth sign-in button sample from the docs page.</p>
            </div>
          </div>
        </article>

        <article className="panel">
          <h2>Available endpoints</h2>
          <div className="mono-list">
            <code>{oauthInfo?.authorizationEndpoint || 'http://localhost:4000/authorize'}</code>
            <code>{oauthInfo?.tokenEndpoint || 'http://localhost:4000/api/sso/token'}</code>
            <code>{oauthInfo?.userinfoEndpoint || 'http://localhost:4000/api/sso/userinfo'}</code>
            <code>{oauthInfo?.discoveryEndpoint || 'http://localhost:4000/.well-known/openid-configuration'}</code>
          </div>
        </article>
      </section>

      <section className="panel">
        <div className="split-heading">
          <h2>Starter apps</h2>
          <Link className="text-link" to="/docs">
            Learn how to connect yours
          </Link>
        </div>
        <div className="catalog-grid">
          {(oauthInfo?.clients || []).map((client) => (
            <article className="app-card" key={client.clientId}>
              <div className="app-card-top">
                <div className="logo-tile">{client.logoText}</div>
                <div>
                  <strong>{client.clientName}</strong>
                  <p>{client.clientType} client</p>
                </div>
              </div>
              <p>{client.description}</p>
              <code>{client.clientId}</code>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function AuthPage({ refreshSession, session }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [mode, setMode] = useState('login');
  const [registerForm, setRegisterForm] = useState(defaultRegisterForm);
  const [loginForm, setLoginForm] = useState(defaultLoginForm);
  const [handleStatus, setHandleStatus] = useState(defaultHandleStatus);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (session?.authenticated) {
      navigate(startPageToPath(session.user.settings?.startPage), { replace: true });
    }
  }, [navigate, session]);

  useEffect(() => {
    const baseHandle = registerForm.desiredHandle || registerForm.displayName;

    if (!baseHandle) {
      setHandleStatus(defaultHandleStatus);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      fetch(
        `/api/auth/handle-availability?handle=${encodeURIComponent(baseHandle)}&seed=${encodeURIComponent(baseHandle)}`,
        { credentials: 'include', signal: controller.signal },
      )
        .then((response) => response.json())
        .then((payload) => {
          setHandleStatus({
            state: payload.available ? 'available' : 'unavailable',
            message: payload.message,
            suggestion: payload.suggestion || '',
            novaAuthId: payload.novaAuthId || '',
          });
        })
        .catch((requestError) => {
          if (requestError.name !== 'AbortError') {
            setHandleStatus({
              state: 'error',
              message: 'Unable to validate that handle right now.',
              suggestion: '',
              novaAuthId: '',
            });
          }
        });
    }, 250);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [registerForm.desiredHandle, registerForm.displayName]);

  async function completeAuth(action) {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      await action();
      const sessionPayload = await refreshSession();
      const fallback = startPageToPath(sessionPayload.user.settings?.startPage);
      navigate(getNextPath(searchParams, fallback), { replace: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="auth-layout">
      <article className="panel">
        <span className="eyebrow">Account access</span>
        <h1>{mode === 'login' ? 'Welcome back' : 'Create your NovaAuth ID'}</h1>
        <p className="lead">
          Use your NovaAuth mailbox, handle, or NovaAuth ID to sign in. New accounts immediately work with OAuth2 app approvals.
        </p>

        <div className="mode-switch">
          <button
            className={mode === 'login' ? 'mode-button active' : 'mode-button'}
            onClick={() => setMode('login')}
            type="button"
          >
            Sign in
          </button>
          <button
            className={mode === 'register' ? 'mode-button active' : 'mode-button'}
            onClick={() => setMode('register')}
            type="button"
          >
            Register
          </button>
        </div>

        {mode === 'login' ? (
          <form
            className="form-grid"
            onSubmit={(event) => {
              event.preventDefault();
              completeAuth(async () => {
                await apiRequest('/api/auth/login', {
                  method: 'POST',
                  body: JSON.stringify(loginForm),
                });
              });
            }}
          >
            <label>
              NovaAuth login
              <input
                onChange={(event) => setLoginForm((current) => ({ ...current, login: event.target.value }))}
                placeholder="handle, mailbox, or handle#NovaAuth"
                value={loginForm.login}
              />
            </label>
            <label>
              Password
              <input
                onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
                type="password"
                value={loginForm.password}
              />
            </label>
            <button className="primary-button" disabled={loading} type="submit">
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        ) : (
          <form
            className="form-grid"
            onSubmit={(event) => {
              event.preventDefault();
              completeAuth(async () => {
                await apiRequest('/api/auth/register', {
                  method: 'POST',
                  body: JSON.stringify(registerForm),
                });
              });
            }}
          >
            <label>
              Display name
              <input
                onChange={(event) => setRegisterForm((current) => ({ ...current, displayName: event.target.value }))}
                value={registerForm.displayName}
              />
            </label>
            <label>
              Desired handle
              <input
                onChange={(event) => setRegisterForm((current) => ({ ...current, desiredHandle: event.target.value }))}
                value={registerForm.desiredHandle}
              />
            </label>
            <label>
              Password
              <input
                minLength={8}
                onChange={(event) => setRegisterForm((current) => ({ ...current, password: event.target.value }))}
                type="password"
                value={registerForm.password}
              />
            </label>
            <div className={`status-line ${handleStatus.state}`}>
              <strong>{handleStatus.message}</strong>
              <span>{handleStatus.novaAuthId || handleStatus.suggestion || 'NovaAuth ID preview will appear here.'}</span>
            </div>
            <button className="primary-button" disabled={loading} type="submit">
              {loading ? 'Creating account...' : 'Create account'}
            </button>
          </form>
        )}

        {error ? <p className="feedback error">{error}</p> : null}
        {message ? <p className="feedback success">{message}</p> : null}
      </article>

      <article className="panel soft">
        <h2>What you unlock</h2>
        <div className="feature-list">
          <div>
            <strong>Reusable identity</strong>
            <p>One account signs into every connected NovaAuth-enabled app.</p>
          </div>
          <div>
            <strong>Developer console</strong>
            <p>Create OAuth clients, choose scopes, register redirect URIs, and rotate secrets.</p>
          </div>
          <div>
            <strong>Consent history</strong>
            <p>Track connected apps and revoke their access from your dashboard.</p>
          </div>
        </div>
      </article>
    </section>
  );
}

function DashboardPage({ refreshSession, session }) {
  const [notifications, setNotifications] = useState([]);
  const [connectedApps, setConnectedApps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([apiRequest('/api/notifications'), apiRequest('/api/account/connected-apps')])
      .then(([notificationPayload, appPayload]) => {
        setNotifications(notificationPayload.notifications || []);
        setConnectedApps(appPayload.apps || []);
      })
      .catch((requestError) => setError(requestError.message))
      .finally(() => setLoading(false));
  }, []);

  async function markAllRead() {
    const payload = await apiRequest('/api/notifications/read', {
      method: 'POST',
      body: JSON.stringify({ markAll: true }),
    });
    setNotifications(payload.notifications || []);
    await refreshSession();
  }

  async function revokeApp(clientId) {
    const payload = await apiRequest('/api/account/connected-apps/revoke', {
      method: 'POST',
      body: JSON.stringify({ clientId }),
    });
    setConnectedApps(payload.apps || []);
    await refreshSession();
  }

  return (
    <div className="page-grid">
      <section className="hero-card compact">
        <div className="hero-copy">
          <span className="eyebrow">Identity dashboard</span>
          <h1>{session.user.displayName}</h1>
          <p className="lead">
            {session.user.novaAuthId} · {session.user.novaEmail}
          </p>
          {session.user.settings?.profileTagline ? <p>{session.user.settings.profileTagline}</p> : null}
        </div>
        <div className="stack">
          <article className="info-card">
            <span className="card-label">Connected apps</span>
            <strong>{connectedApps.length}</strong>
          </article>
          <article className="info-card">
            <span className="card-label">Unread inbox</span>
            <strong>{session.inbox?.unreadCount || 0}</strong>
          </article>
        </div>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="split-heading">
            <h2>Notifications</h2>
            <button className="ghost-button" onClick={markAllRead} type="button">
              Mark all read
            </button>
          </div>
          {loading ? <p>Loading notifications...</p> : null}
          {error ? <p className="feedback error">{error}</p> : null}
          <div className="stack">
            {notifications.map((item) => (
              <article className="info-card" key={item.id}>
                <div className="split-heading">
                  <strong>{item.title}</strong>
                  <small>{new Date(item.createdAt).toLocaleString()}</small>
                </div>
                <p>{item.body}</p>
              </article>
            ))}
            {!notifications.length && !loading ? <p>No notifications yet.</p> : null}
          </div>
        </article>

        <article className="panel">
          <h2>Connected apps</h2>
          <div className="stack">
            {connectedApps.map((app) => (
              <article className="app-card" key={app.clientId}>
                <div className="app-card-top">
                  <div className="logo-tile">{app.logoText}</div>
                  <div>
                    <strong>{app.clientName}</strong>
                    <p>{app.description}</p>
                  </div>
                </div>
                <p>Scopes: {app.scopes.join(', ')}</p>
                <small>Last used: {new Date(app.lastUsedAt).toLocaleString()}</small>
                <div className="button-row">
                  {app.applicationUrl ? (
                    <a className="ghost-button" href={app.applicationUrl} rel="noreferrer" target="_blank">
                      Open app
                    </a>
                  ) : null}
                  <button className="text-button" onClick={() => revokeApp(app.clientId)} type="button">
                    Revoke access
                  </button>
                </div>
              </article>
            ))}
            {!connectedApps.length && !loading ? (
              <p>No connected apps yet. Approvals will show up here after you use Sign in with NovaAuth.</p>
            ) : null}
          </div>
        </article>
      </section>
    </div>
  );
}

function AppsPage({ oauthInfo, session }) {
  const [apps, setApps] = useState([]);
  const [scopeOptions, setScopeOptions] = useState([]);
  const [form, setForm] = useState(defaultAppForm(session.user.settings));
  const [editingId, setEditingId] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [latestSecret, setLatestSecret] = useState('');

  async function loadApps() {
    setLoading(true);
    try {
      const payload = await apiRequest('/api/developer/apps');
      setApps(payload.apps || []);
      setScopeOptions(payload.scopes || []);
      setForm((current) =>
        current.clientName || editingId
          ? current
          : defaultAppForm(payload.defaults || session.user.settings),
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApps();
  }, []);

  function toggleScope(field, scopeKey) {
    setForm((current) => {
      const nextValues = current[field].includes(scopeKey)
        ? current[field].filter((value) => value !== scopeKey)
        : [...current[field], scopeKey];
      const withOpenId = nextValues.includes('openid') ? nextValues : ['openid', ...nextValues];

      if (field === 'allowedScopes') {
        return {
          ...current,
          allowedScopes: withOpenId,
          defaultScopes: current.defaultScopes.filter((scope) => withOpenId.includes(scope)),
        };
      }

      return {
        ...current,
        [field]: withOpenId,
      };
    });
  }

  function loadIntoEditor(app) {
    setEditingId(app.clientId);
    setLatestSecret('');
    setForm({
      clientName: app.clientName,
      description: app.description,
      applicationUrl: app.applicationUrl,
      redirectUris: joinLines(app.redirectUris),
      allowedOrigins: joinLines(app.allowedOrigins),
      clientType: app.clientType,
      allowedScopes: app.allowedScopes,
      defaultScopes: app.defaultScopes,
      logoText: app.logoText,
      status: app.status,
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');
    setMessage('');
    setLatestSecret('');

    const path = editingId ? `/api/developer/apps/${editingId}/update` : '/api/developer/apps';

    try {
      const payload = await apiRequest(path, {
        method: 'POST',
        body: JSON.stringify(form),
      });
      setMessage(editingId ? 'Developer app updated.' : 'Developer app created.');
      if (payload.app?.clientSecret) {
        setLatestSecret(payload.app.clientSecret);
      }
      setEditingId('');
      setForm(defaultAppForm(session.user.settings));
      await loadApps();
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function rotateSecret(clientId) {
    setError('');
    setMessage('');
    try {
      const payload = await apiRequest(`/api/developer/apps/${clientId}/rotate-secret`, {
        method: 'POST',
      });
      setLatestSecret(payload.clientSecret);
      setMessage(`Secret rotated for ${clientId}.`);
      await loadApps();
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  return (
    <div className="page-grid">
      <section className="hero-card compact">
        <div className="hero-copy">
          <span className="eyebrow">Developer console</span>
          <h1>OAuth apps</h1>
          <p className="lead">
            Register the apps that will show the NovaAuth sign-in button and send users through the OAuth2 consent flow.
          </p>
        </div>
        <div className="stack">
          <article className="info-card">
            <span className="card-label">Authorize endpoint</span>
            <code>{oauthInfo?.authorizationEndpoint}</code>
          </article>
          <article className="info-card">
            <span className="card-label">Token endpoint</span>
            <code>{oauthInfo?.tokenEndpoint}</code>
          </article>
        </div>
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="split-heading">
            <h2>{editingId ? `Edit ${editingId}` : 'Register a new app'}</h2>
            {editingId ? (
              <button
                className="text-button"
                onClick={() => {
                  setEditingId('');
                  setForm(defaultAppForm(session.user.settings));
                }}
                type="button"
              >
                Cancel edit
              </button>
            ) : null}
          </div>

          <form className="form-grid" onSubmit={handleSubmit}>
            <label>
              App name
              <input
                onChange={(event) => setForm((current) => ({ ...current, clientName: event.target.value }))}
                value={form.clientName}
              />
            </label>
            <label>
              Description
              <textarea
                onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
                rows={3}
                value={form.description}
              />
            </label>
            <label>
              Application URL
              <input
                onChange={(event) => setForm((current) => ({ ...current, applicationUrl: event.target.value }))}
                placeholder="https://yourapp.com"
                value={form.applicationUrl}
              />
            </label>
            <label>
              Redirect URIs
              <textarea
                onChange={(event) => setForm((current) => ({ ...current, redirectUris: event.target.value }))}
                placeholder="One URL per line"
                rows={4}
                value={form.redirectUris}
              />
            </label>
            <label>
              Allowed origins
              <textarea
                onChange={(event) => setForm((current) => ({ ...current, allowedOrigins: event.target.value }))}
                placeholder="Optional. One origin per line"
                rows={3}
                value={form.allowedOrigins}
              />
            </label>
            <label>
              Logo text
              <input
                maxLength={3}
                onChange={(event) => setForm((current) => ({ ...current, logoText: event.target.value }))}
                value={form.logoText}
              />
            </label>

            <div className="mode-switch">
              <button
                className={form.clientType === 'public' ? 'mode-button active' : 'mode-button'}
                onClick={() => setForm((current) => ({ ...current, clientType: 'public' }))}
                type="button"
              >
                Public
              </button>
              <button
                className={form.clientType === 'confidential' ? 'mode-button active' : 'mode-button'}
                onClick={() => setForm((current) => ({ ...current, clientType: 'confidential' }))}
                type="button"
              >
                Confidential
              </button>
            </div>

            <div className="checkbox-group">
              <strong>Allowed scopes</strong>
              {scopeOptions.map((scope) => (
                <label className="checkline" key={scope.key}>
                  <input
                    checked={form.allowedScopes.includes(scope.key)}
                    disabled={scope.key === 'openid'}
                    onChange={() => toggleScope('allowedScopes', scope.key)}
                    type="checkbox"
                  />
                  <span>
                    <strong>{scope.key}</strong>
                    <small>{scope.description}</small>
                  </span>
                </label>
              ))}
            </div>

            <div className="checkbox-group">
              <strong>Default scopes</strong>
              {scopeOptions
                .filter((scope) => form.allowedScopes.includes(scope.key))
                .map((scope) => (
                  <label className="checkline" key={scope.key}>
                    <input
                      checked={form.defaultScopes.includes(scope.key)}
                      disabled={scope.key === 'openid'}
                      onChange={() => toggleScope('defaultScopes', scope.key)}
                      type="checkbox"
                    />
                    <span>{scope.key}</span>
                  </label>
                ))}
            </div>

            <button className="primary-button" type="submit">
              {editingId ? 'Save app' : 'Create app'}
            </button>
          </form>

          {message ? <p className="feedback success">{message}</p> : null}
          {error ? <p className="feedback error">{error}</p> : null}
          {latestSecret ? (
            <div className="status-line available">
              <strong>Copy this secret now</strong>
              <code>{latestSecret}</code>
            </div>
          ) : null}
        </article>

        <article className="panel">
          <h2>Your registered apps</h2>
          {loading ? <p>Loading apps...</p> : null}
          <div className="stack">
            {apps.map((app) => (
              <article className="app-card" key={app.clientId}>
                <div className="app-card-top">
                  <div className="logo-tile">{app.logoText}</div>
                  <div>
                    <strong>{app.clientName}</strong>
                    <p>{app.clientId}</p>
                  </div>
                </div>
                <p>{app.description}</p>
                <small>{app.clientType} · {app.status}</small>
                <code>{app.redirectUris[0]}</code>
                <div className="button-row">
                  <button className="ghost-button" onClick={() => loadIntoEditor(app)} type="button">
                    Edit
                  </button>
                  {app.clientType === 'confidential' ? (
                    <button className="text-button" onClick={() => rotateSecret(app.clientId)} type="button">
                      Rotate secret
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
            {!apps.length && !loading ? <p>No apps yet. Create your first client from the form.</p> : null}
          </div>
        </article>
      </section>
    </div>
  );
}

function SettingsPage({ applyUserUpdate, refreshSession, session }) {
  const [settings, setSettings] = useState(session.user.settings);
  const [scopeOptions, setScopeOptions] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    apiRequest('/api/account/settings')
      .then((payload) => {
        setSettings(payload.settings);
        setScopeOptions(payload.availableScopes || []);
      })
      .catch((requestError) => setError(requestError.message));
  }, []);

  function toggleScope(scopeKey) {
    setSettings((current) => {
      const next = current.developerDefaultScopes.includes(scopeKey)
        ? current.developerDefaultScopes.filter((item) => item !== scopeKey)
        : [...current.developerDefaultScopes, scopeKey];
      return {
        ...current,
        developerDefaultScopes: next.includes('openid') ? next : ['openid', ...next],
      };
    });
  }

  async function handleSave(event) {
    event.preventDefault();
    setError('');
    setMessage('');

    try {
      const payload = await apiRequest('/api/account/settings', {
        method: 'POST',
        body: JSON.stringify(settings),
      });
      setSettings(payload.settings);
      applyUserUpdate(payload.user);
      await refreshSession();
      setMessage('Settings saved.');
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  return (
    <section className="panel">
      <span className="eyebrow">Preferences</span>
      <h1>Settings</h1>
      <p className="lead">
        Theme defaults to your browser and OS preference, but you can override it here if you want.
      </p>

      <form className="form-grid" onSubmit={handleSave}>
        <div className="checkbox-group">
          <strong>Theme</strong>
          <div className="mode-switch">
            {['system', 'light', 'dark'].map((theme) => (
              <button
                className={settings.themePreference === theme ? 'mode-button active' : 'mode-button'}
                key={theme}
                onClick={() => setSettings((current) => ({ ...current, themePreference: theme }))}
                type="button"
              >
                {theme}
              </button>
            ))}
          </div>
        </div>

        <label>
          Profile tagline
          <input
            maxLength={120}
            onChange={(event) => setSettings((current) => ({ ...current, profileTagline: event.target.value }))}
            value={settings.profileTagline}
          />
        </label>

        <div className="checkbox-group">
          <strong>Start page</strong>
          <div className="mode-switch">
            {['dashboard', 'apps', 'settings', 'docs'].map((page) => (
              <button
                className={settings.startPage === page ? 'mode-button active' : 'mode-button'}
                key={page}
                onClick={() => setSettings((current) => ({ ...current, startPage: page }))}
                type="button"
              >
                {page}
              </button>
            ))}
          </div>
        </div>

        <div className="checkbox-group">
          <strong>Layout and notifications</strong>
          {[
            ['compactMode', 'Use compact layout'],
            ['emailUpdates', 'Receive product update emails'],
            ['securityAlerts', 'Keep security alerts enabled'],
          ].map(([key, label]) => (
            <label className="checkline" key={key}>
              <input
                checked={Boolean(settings[key])}
                onChange={(event) => setSettings((current) => ({ ...current, [key]: event.target.checked }))}
                type="checkbox"
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        <div className="checkbox-group">
          <strong>Developer defaults</strong>
          <div className="mode-switch">
            {['public', 'confidential'].map((clientType) => (
              <button
                className={settings.developerDefaultClientType === clientType ? 'mode-button active' : 'mode-button'}
                key={clientType}
                onClick={() => setSettings((current) => ({ ...current, developerDefaultClientType: clientType }))}
                type="button"
              >
                {clientType}
              </button>
            ))}
          </div>
          {scopeOptions.map((scope) => (
            <label className="checkline" key={scope.key}>
              <input
                checked={settings.developerDefaultScopes.includes(scope.key)}
                disabled={scope.key === 'openid'}
                onChange={() => toggleScope(scope.key)}
                type="checkbox"
              />
              <span>
                <strong>{scope.key}</strong>
                <small>{scope.description}</small>
              </span>
            </label>
          ))}
        </div>

        <button className="primary-button" type="submit">
          Save settings
        </button>
      </form>

      {message ? <p className="feedback success">{message}</p> : null}
      {error ? <p className="feedback error">{error}</p> : null}
    </section>
  );
}

function DocsPage({ oauthInfo, session }) {
  const [apps, setApps] = useState([]);

  useEffect(() => {
    if (!session?.authenticated) {
      return;
    }

    apiRequest('/api/developer/apps')
      .then((payload) => setApps(payload.apps || []))
      .catch(() => {});
  }, [session]);

  const exampleApp = apps[0];
  const exampleClientId = exampleApp?.clientId || 'your-client-id';
  const exampleRedirectUri = exampleApp?.redirectUris?.[0] || 'https://your-app.com/auth/callback';
  const exampleScopes = (exampleApp?.defaultScopes || ['openid', 'profile', 'email']).join(' ');

  return (
    <div className="page-grid">
      <section className="hero-card compact">
        <div className="hero-copy">
          <span className="eyebrow">Developer documentation</span>
          <h1>Connect your app to NovaAuth</h1>
          <p className="lead">
            Register a client in the Apps page, then send users to the authorize endpoint and exchange the returned code for tokens.
          </p>
        </div>
        <div className="stack">
          <article className="info-card">
            <span className="card-label">Discovery</span>
            <code>{oauthInfo?.discoveryEndpoint}</code>
          </article>
          <article className="info-card">
            <span className="card-label">JWT keys</span>
            <code>{oauthInfo?.jwksUri}</code>
          </article>
        </div>
      </section>

      <section className="content-grid">
        <article className="panel">
          <h2>1. Register your OAuth client</h2>
          <p>Go to the Apps page and configure your app name, redirect URIs, scopes, and whether the client is public or confidential.</p>

          <h2>2. Add a NovaAuth sign-in button</h2>
          <pre className="code-block">
            <code>{`<button class="novaauth-button">Sign in with NovaAuth</button>`}</code>
          </pre>

          <h2>3. Redirect to the authorize endpoint</h2>
          <pre className="code-block">
            <code>{`GET ${oauthInfo?.authorizationEndpoint || 'http://localhost:4000/authorize'}?client_id=${exampleClientId}&redirect_uri=${encodeURIComponent(exampleRedirectUri)}&response_type=code&scope=${encodeURIComponent(exampleScopes)}&state=YOUR_STATE&code_challenge=PKCE_CHALLENGE&code_challenge_method=S256`}</code>
          </pre>

          <h2>4. Exchange the code for tokens</h2>
          <pre className="code-block">
            <code>{`curl -X POST ${oauthInfo?.tokenEndpoint || 'http://localhost:4000/api/sso/token'} \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "client_id=${exampleClientId}" \\
  -d "redirect_uri=${exampleRedirectUri}" \\
  -d "code=RETURNED_CODE" \\
  -d "code_verifier=ORIGINAL_PKCE_VERIFIER"`}</code>
          </pre>
        </article>

        <article className="panel">
          <h2>What NovaAuth returns</h2>
          <p>The token endpoint returns an access token, refresh token, ID token, token type, expiry, and granted scope string.</p>
          <pre className="code-block">
            <code>{`{
  "access_token": "jwt-access-token",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "refresh-token",
  "id_token": "jwt-id-token",
  "scope": "${exampleScopes}"
}`}</code>
          </pre>

          <h2>Profile data</h2>
          <p>Call the userinfo endpoint with the bearer access token to read the signed-in NovaAuth identity.</p>
          <pre className="code-block">
            <code>{`fetch("${oauthInfo?.userinfoEndpoint || 'http://localhost:4000/api/sso/userinfo'}", {
  headers: { Authorization: "Bearer ACCESS_TOKEN" }
})`}</code>
          </pre>

          <h2>Recommended flow</h2>
          <div className="feature-list">
            <div>
              <strong>Browser apps</strong>
              <p>Use Authorization Code + PKCE with a public client. Never ship a client secret to the browser.</p>
            </div>
            <div>
              <strong>Backend apps</strong>
              <p>Use a confidential client and keep the secret on the server so you can refresh and introspect securely.</p>
            </div>
            <div>
              <strong>Consent screen</strong>
              <p>NovaAuth hosts the approval page at `/authorize` and tracks granted scopes per user and app.</p>
            </div>
          </div>
        </article>
      </section>
    </div>
  );
}

function AuthorizePage({ refreshSession, session }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [context, setContext] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const query = searchParams.toString();

    apiRequest(`/api/sso/authorize/context?${query}`)
      .then((payload) => setContext(payload))
      .catch((requestError) => setError(requestError.message))
      .finally(() => setLoading(false));
  }, [searchParams, session]);

  if (loading) {
    return (
      <div className="screen-center">
        <div className="loading-card">
          <h1>Preparing consent screen</h1>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <section className="panel">
        <h1>Unable to continue</h1>
        <p className="feedback error">{error}</p>
      </section>
    );
  }

  if (!context?.authenticated) {
    const next = `/authorize?${searchParams.toString()}`;
    return (
      <section className="auth-layout">
        <article className="panel">
          <span className="eyebrow">Authorization required</span>
          <h1>Sign in to continue</h1>
          <p className="lead">
            {context?.client?.clientName || 'This app'} wants to use your NovaAuth identity.
          </p>
          <button
            className="primary-button"
            onClick={() => navigate(`/auth?next=${encodeURIComponent(next)}`)}
            type="button"
          >
            Continue to sign in
          </button>
        </article>
      </section>
    );
  }

  async function submitDecision(approve) {
    const payload = await apiRequest('/api/sso/authorize', {
      method: 'POST',
      body: JSON.stringify({
        ...Object.fromEntries(searchParams.entries()),
        approve,
      }),
    });

    if (!approve) {
      window.location.assign(payload.redirectTo);
      return;
    }

    await refreshSession();
    window.location.assign(payload.redirectTo);
  }

  return (
    <section className="auth-layout">
      <article className="panel">
        <span className="eyebrow">App consent</span>
        <h1>{context.client.clientName}</h1>
        <p className="lead">{context.client.description}</p>
        <div className="stack">
          {context.requestedScopes.map((scope) => (
            <article className="info-card" key={scope.scope}>
              <strong>{scope.scope}</strong>
              <p>{scope.description}</p>
            </article>
          ))}
        </div>
        <div className="button-row">
          <button className="primary-button" onClick={() => submitDecision(true)} type="button">
            Approve and continue
          </button>
          <button className="ghost-button" onClick={() => submitDecision(false)} type="button">
            Cancel
          </button>
        </div>
      </article>

      <article className="panel soft">
        <h2>Signed in as</h2>
        <p>{context.user.novaAuthId}</p>
        <p>{context.user.novaEmail}</p>
        {context.priorGrant ? (
          <div className="status-line available">
            <strong>Previously approved</strong>
            <span>{context.priorGrant.scopes.join(', ')}</span>
          </div>
        ) : null}
      </article>
    </section>
  );
}

function NotFoundPage() {
  return (
    <section className="panel">
      <h1>Page not found</h1>
      <p>This route does not exist yet. Try the dashboard, docs, or apps page.</p>
      <Link className="primary-button" to="/">
        Back home
      </Link>
    </section>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
