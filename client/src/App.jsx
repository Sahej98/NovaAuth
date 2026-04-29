import { useEffect, useMemo, useState } from 'react';
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

function getAuthorizeParams() {
  const params = new URLSearchParams(window.location.search);
  return Object.fromEntries(params.entries());
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

export default function App() {
  const [mode, setMode] = useState('login');
  const [registerForm, setRegisterForm] = useState(defaultRegisterForm);
  const [loginForm, setLoginForm] = useState(defaultLoginForm);
  const [handleStatus, setHandleStatus] = useState({
    state: 'idle',
    message: 'Choose your NovaAuth handle.',
    suggestion: '',
    novaAuthId: '',
  });
  const [session, setSession] = useState(null);
  const [appCatalog, setAppCatalog] = useState(null);
  const [authorizeContext, setAuthorizeContext] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [booting, setBooting] = useState(true);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const authorizeParams = useMemo(() => getAuthorizeParams(), []);
  const isAuthorizeRoute = window.location.pathname === '/authorize';

  useEffect(() => {
    Promise.all([
      apiRequest('/api/auth/session').catch(() => ({ authenticated: false })),
      apiRequest('/api/sso/apps'),
    ])
      .then(async ([sessionPayload, appsPayload]) => {
        setAppCatalog(appsPayload);

        if (sessionPayload.authenticated) {
          setSession(sessionPayload);
          const inboxPayload = await apiRequest('/api/notifications').catch(() => ({
            notifications: [],
            unreadCount: sessionPayload.inbox?.unreadCount || 0,
          }));
          setNotifications(inboxPayload.notifications || []);
          setUnreadCount(inboxPayload.unreadCount || 0);
        }
      })
      .catch((requestError) => {
        setError(requestError.message);
      })
      .finally(() => {
        setBooting(false);
      });
  }, []);

  useEffect(() => {
    if (!isAuthorizeRoute) {
      return;
    }

    const query = new URLSearchParams(authorizeParams).toString();

    apiRequest(`/api/sso/authorize/context?${query}`)
      .then((payload) => {
        setAuthorizeContext(payload);
      })
      .catch((requestError) => {
        setError(requestError.message);
      });
  }, [authorizeParams, isAuthorizeRoute, session]);

  useEffect(() => {
    const baseHandle = registerForm.desiredHandle || registerForm.displayName || '';

    if (!baseHandle) {
      setHandleStatus({
        state: 'idle',
        message: 'Choose your NovaAuth handle.',
        suggestion: '',
        novaAuthId: '',
      });
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => {
      fetch(
        `/api/auth/handle-availability?handle=${encodeURIComponent(baseHandle)}&seed=${encodeURIComponent(baseHandle)}`,
        { signal: controller.signal, credentials: 'include' },
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
      controller.abort();
      clearTimeout(timer);
    };
  }, [registerForm.desiredHandle, registerForm.displayName]);

  async function refreshSession() {
    const [sessionPayload, notificationPayload] = await Promise.all([
      apiRequest('/api/auth/session'),
      apiRequest('/api/notifications').catch(() => ({ notifications: [], unreadCount: 0 })),
    ]);
    setSession(sessionPayload);
    setNotifications(notificationPayload.notifications || []);
    setUnreadCount(notificationPayload.unreadCount || 0);
    return sessionPayload;
  }

  async function handleRegister(event) {
    event.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const payload = await apiRequest('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(registerForm),
      });
      setSession(payload);
      setRegisterForm(defaultRegisterForm);
      const inboxPayload = await apiRequest('/api/notifications');
      setNotifications(inboxPayload.notifications || []);
      setUnreadCount(inboxPayload.unreadCount || 0);
      setMessage(`NovaAuth ID created: ${payload.user.novaAuthId}`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const payload = await apiRequest('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(loginForm),
      });
      setSession(payload);
      setLoginForm(defaultLoginForm);
      const inboxPayload = await apiRequest('/api/notifications');
      setNotifications(inboxPayload.notifications || []);
      setUnreadCount(inboxPayload.unreadCount || 0);
      setMessage(`Signed in as ${payload.user.novaAuthId}`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      await apiRequest('/api/auth/logout', {
        method: 'POST',
      });
      setSession(null);
      setNotifications([]);
      setUnreadCount(0);
      setMessage('Central session closed.');
      if (isAuthorizeRoute) {
        const payload = await apiRequest(
          `/api/sso/authorize/context?${new URLSearchParams(authorizeParams).toString()}`,
        );
        setAuthorizeContext(payload);
      }
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleAuthorizeDecision(approve) {
    setLoading(true);
    setError('');
    setMessage('');

    try {
      const payload = await apiRequest('/api/sso/authorize', {
        method: 'POST',
        body: JSON.stringify({
          ...authorizeParams,
          approve,
        }),
      });

      if (payload.redirectTo) {
        window.location.href = payload.redirectTo;
      }
    } catch (requestError) {
      setError(requestError.message);
      setLoading(false);
    }
  }

  async function markNotificationsRead(ids = [], markAll = false) {
    if (!session) {
      return;
    }

    try {
      const payload = await apiRequest('/api/notifications/read', {
        method: 'POST',
        body: JSON.stringify({
          ids,
          markAll,
        }),
      });
      setNotifications(payload.notifications || []);
      setUnreadCount(payload.unreadCount || 0);
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  function applySuggestion() {
    if (!handleStatus.suggestion) {
      return;
    }

    setRegisterForm((current) => ({
      ...current,
      desiredHandle: handleStatus.suggestion,
    }));
  }

  async function handleContinueSession() {
    setLoading(true);
    setError('');

    try {
      const refreshedSession = await refreshSession();
      if (isAuthorizeRoute) {
        const context = await apiRequest(
          `/api/sso/authorize/context?${new URLSearchParams(authorizeParams).toString()}`,
        );
        setAuthorizeContext(context);
      }
      setMessage(`Continuing SSO as ${refreshedSession.user.novaAuthId}.`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  if (booting) {
    return (
      <main className="shell">
        <section className="hero-band">
          <p className="eyebrow">NovaAuth SSO</p>
          <h1>Preparing your identity workspace...</h1>
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <section className="hero-band">
        <div className="hero-copy">
          <p className="eyebrow">NovaAuth Identity Cloud</p>
          <h1>One handle for every app you launch.</h1>
          <p className="lead">
            NovaAuth is now handle-first. Users create a NovaAuth ID, get a built-in Nova mailbox,
            receive notifications inside the platform, and sign into connected apps through one
            SSO flow.
          </p>
        </div>

        <div className="hero-rail">
          <article className="float-card accent-card">
            <span className="card-label">Identity</span>
            <strong>{handleStatus.novaAuthId || 'sahej98#NovaAuth'}</strong>
            <p>Global across all your apps.</p>
          </article>
          <article className="float-card">
            <span className="card-label">Nova Mail</span>
            <strong>{session?.user.novaEmail || 'sahej98@novaauth.id'}</strong>
            <p>System-owned mailbox attached to the NovaAuth account.</p>
          </article>
          <article className="float-card">
            <span className="card-label">Inbox</span>
            <strong>{unreadCount} unread</strong>
            <p>Notifications and identity events stay inside NovaAuth.</p>
          </article>
        </div>
      </section>

      {isAuthorizeRoute ? (
        <section className="flow-band">
          <div className="flow-column">
            <p className="eyebrow">Authorization Request</p>
            {authorizeContext?.client ? (
              <>
                <div className="app-row">
                  <div className="app-badge">{authorizeContext.client.logoText || 'NA'}</div>
                  <div>
                    <h2>{authorizeContext.client.clientName}</h2>
                    <p className="session-meta">{authorizeContext.client.description}</p>
                  </div>
                </div>

                <div className="strip-grid">
                  <article className="strip-card">
                    <span className="card-label">Redirect URI</span>
                    <strong>{authorizeContext.client.redirectUri}</strong>
                  </article>
                  <article className="strip-card">
                    <span className="card-label">Requested Scopes</span>
                    <strong>{authorizeContext.requestedScopes.map((item) => item.scope).join(', ')}</strong>
                  </article>
                </div>

                {session ? (
                  <>
                    <div className="identity-banner">
                      <div>
                        <span className="card-label">Signed In</span>
                        <h3>{session.user.novaAuthId}</h3>
                      </div>
                      <div>
                        <span className="card-label">Nova Mail</span>
                        <strong>{session.user.novaEmail}</strong>
                      </div>
                    </div>

                    <div className="scope-list">
                      {authorizeContext.requestedScopes.map((scope) => (
                        <article key={scope.scope} className="scope-item">
                          <strong>{scope.scope}</strong>
                          <p>{scope.description}</p>
                        </article>
                      ))}
                    </div>

                    <div className="action-row">
                      <button
                        type="button"
                        className="ghost-button"
                        onClick={() => handleAuthorizeDecision(false)}
                        disabled={loading}
                      >
                        Deny
                      </button>
                      <button
                        type="button"
                        className="primary-button"
                        onClick={() => handleAuthorizeDecision(true)}
                        disabled={loading}
                      >
                        {loading ? 'Redirecting...' : `Continue to ${authorizeContext.client.clientName}`}
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="lead compact">
                      Sign in with your NovaAuth ID to finish this app connection.
                    </p>
                    <AuthForms
                      mode={mode}
                      setMode={setMode}
                      registerForm={registerForm}
                      setRegisterForm={setRegisterForm}
                      loginForm={loginForm}
                      setLoginForm={setLoginForm}
                      handleStatus={handleStatus}
                      applySuggestion={applySuggestion}
                      handleRegister={handleRegister}
                      handleLogin={handleLogin}
                      loading={loading}
                    />
                  </>
                )}
              </>
            ) : (
              <p className="lead compact">Waiting for a valid SSO request...</p>
            )}
          </div>
        </section>
      ) : (
        <section className="workspace-band">
          <div className="workspace-main">
            {session ? (
              <>
                <div className="identity-banner">
                  <div>
                    <span className="card-label">Central Session</span>
                    <h2>{session.user.novaAuthId}</h2>
                    <p className="session-meta">{session.user.displayName}</p>
                  </div>
                  <div className="identity-meta">
                    <div>
                      <span className="card-label">Nova Mail</span>
                      <strong>{session.user.novaEmail}</strong>
                    </div>
                    <div>
                      <span className="card-label">Session Expires</span>
                      <strong>{new Date(session.session.expiresAt).toLocaleString()}</strong>
                    </div>
                  </div>
                </div>

                <div className="action-row">
                  <button className="ghost-button" type="button" onClick={handleContinueSession} disabled={loading}>
                    Refresh session
                  </button>
                  <button className="ghost-button" type="button" onClick={() => markNotificationsRead([], true)}>
                    Mark inbox read
                  </button>
                  <button className="primary-button" type="button" onClick={handleLogout} disabled={loading}>
                    {loading ? 'Closing session...' : 'Log out'}
                  </button>
                </div>

                <div className="wide-grid">
                  <article className="wide-card">
                    <span className="card-label">Token Endpoints</span>
                    <div className="status-row">
                      <code>/authorize</code>
                      <code>/api/sso/token</code>
                      <code>/api/sso/userinfo</code>
                      <code>/.well-known/openid-configuration</code>
                    </div>
                  </article>

                  <article className="wide-card">
                    <span className="card-label">Mailbox Identity</span>
                    <p className="body-copy">
                      Personal email is no longer required for account creation. NovaAuth issues a
                      platform-owned mailbox that stays tied to the same handle everywhere.
                    </p>
                  </article>
                </div>
              </>
            ) : (
              <AuthForms
                mode={mode}
                setMode={setMode}
                registerForm={registerForm}
                setRegisterForm={setRegisterForm}
                loginForm={loginForm}
                setLoginForm={setLoginForm}
                handleStatus={handleStatus}
                applySuggestion={applySuggestion}
                handleRegister={handleRegister}
                handleLogin={handleLogin}
                loading={loading}
              />
            )}

            {message ? <p className="feedback success">{message}</p> : null}
            {error ? <p className="feedback error">{error}</p> : null}
          </div>

          <aside className="workspace-side">
            <div className="side-section">
              <p className="eyebrow">Nova Inbox</p>
              <h2>Notifications live here.</h2>
              <p className="body-copy">
                Use NovaAuth as the source of identity events, product announcements, and system
                messaging for every connected app.
              </p>
            </div>

            <div className="inbox-list">
              {notifications.length ? (
                notifications.map((notification) => (
                  <article
                    key={notification.id}
                    className={notification.readAt ? 'inbox-item read' : 'inbox-item'}
                  >
                    <div className="inbox-top">
                      <strong>{notification.title}</strong>
                      {!notification.readAt ? <span className="pill">new</span> : null}
                    </div>
                    <p>{notification.body}</p>
                    <div className="inbox-actions">
                      <span>{new Date(notification.createdAt).toLocaleString()}</span>
                      {!notification.readAt ? (
                        <button
                          type="button"
                          className="text-button"
                          onClick={() => markNotificationsRead([notification.id])}
                        >
                          Mark read
                        </button>
                      ) : null}
                    </div>
                  </article>
                ))
              ) : (
                <article className="inbox-item empty">
                  <strong>No notifications yet</strong>
                  <p>Your NovaAuth inbox will collect welcome messages, app events, and security alerts.</p>
                </article>
              )}
            </div>
          </aside>
        </section>
      )}

      <section className="apps-band">
        <div className="apps-header">
          <p className="eyebrow">Registered Apps</p>
          <h2>SSO clients and integration surface.</h2>
        </div>

        <div className="apps-grid">
          {(appCatalog?.clients || []).map((client) => (
            <article key={client.clientId} className="app-card">
              <div className="app-card-top">
                <div className="mini-badge">{client.logoText || 'NA'}</div>
                <div>
                  <strong>
                    {client.clientName} <span className="muted">({client.clientType})</span>
                  </strong>
                  <p>{client.description}</p>
                </div>
              </div>
              <code>{client.clientId}</code>
            </article>
          ))}
        </div>

        <div className="protocol-strip">
          <article className="strip-card">
            <span className="card-label">1. Redirect user</span>
            <p>
              Send the browser to <code>{appCatalog?.authorizationEndpoint || '/authorize'}</code>{' '}
              with PKCE, scope, state, and redirect URI details.
            </p>
          </article>
          <article className="strip-card">
            <span className="card-label">2. Exchange code</span>
            <p>
              Post to <code>/api/sso/token</code> for short-lived access tokens and rotating refresh
              tokens.
            </p>
          </article>
          <article className="strip-card">
            <span className="card-label">3. Use Nova identity</span>
            <p>
              Trust <code>NovaAuth ID</code>, <code>nova mail</code>, and platform notifications
              from one central service.
            </p>
          </article>
        </div>
      </section>
    </main>
  );
}

function AuthForms({
  mode,
  setMode,
  registerForm,
  setRegisterForm,
  loginForm,
  setLoginForm,
  handleStatus,
  applySuggestion,
  handleRegister,
  handleLogin,
  loading,
}) {
  return (
    <div className="auth-stack">
      <div className="mode-switch">
        <button
          type="button"
          className={mode === 'login' ? 'mode-button active' : 'mode-button'}
          onClick={() => setMode('login')}
        >
          Sign in
        </button>
        <button
          type="button"
          className={mode === 'register' ? 'mode-button active' : 'mode-button'}
          onClick={() => setMode('register')}
        >
          Create NovaAuth ID
        </button>
      </div>

      {mode === 'register' ? (
        <form className="auth-form" onSubmit={handleRegister}>
          <label>
            Display name
            <input
              value={registerForm.displayName}
              onChange={(event) =>
                setRegisterForm((current) => ({ ...current, displayName: event.target.value }))
              }
              placeholder="Sahej"
            />
          </label>

          <label>
            Custom handle
            <div className="handle-input">
              <input
                value={registerForm.desiredHandle}
                onChange={(event) =>
                  setRegisterForm((current) => ({ ...current, desiredHandle: event.target.value }))
                }
                placeholder="sahej98"
              />
              <span>#NovaAuth</span>
            </div>
          </label>

          <div className={`handle-status ${handleStatus.state}`}>
            <span>{handleStatus.message}</span>
            {handleStatus.suggestion && handleStatus.suggestion !== registerForm.desiredHandle ? (
              <button type="button" className="text-button" onClick={applySuggestion}>
                Use {handleStatus.suggestion}#NovaAuth
              </button>
            ) : null}
          </div>

          <label>
            Password
            <input
              type="password"
              value={registerForm.password}
              onChange={(event) =>
                setRegisterForm((current) => ({ ...current, password: event.target.value }))
              }
              placeholder="At least 8 characters"
            />
          </label>

          <button className="primary-button" type="submit" disabled={loading}>
            {loading ? 'Creating account...' : 'Create handle-first identity'}
          </button>
        </form>
      ) : (
        <form className="auth-form" onSubmit={handleLogin}>
          <label>
            Nova mailbox, handle, or NovaAuth ID
            <input
              value={loginForm.login}
              onChange={(event) =>
                setLoginForm((current) => ({ ...current, login: event.target.value }))
              }
              placeholder="sahej98@novaauth.id"
            />
          </label>

          <label>
            Password
            <input
              type="password"
              value={loginForm.password}
              onChange={(event) =>
                setLoginForm((current) => ({ ...current, password: event.target.value }))
              }
              placeholder="Your password"
            />
          </label>

          <button className="primary-button" type="submit" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in to NovaAuth'}
          </button>
        </form>
      )}
    </div>
  );
}
