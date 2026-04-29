const http = require('http');
const { URL } = require('url');
const {
  PORT,
  CLIENT_ORIGIN,
  ISSUER,
  PORTAL_ORIGIN,
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
  AUTH_CODE_TTL_MS,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_MS,
  SCOPE_DESCRIPTIONS,
  createClientSecret,
  getClientById,
  listPublicClients,
  readClients,
  toPublicClient,
  writeClients,
  getJwks,
} = require('./lib/config');
const {
  createDefaultUserSettings,
  normalizeUserSettings,
  readStore,
  writeStore,
} = require('./lib/store');
const {
  sendJson,
  redirect,
  parseBody,
  parseCookies,
  setCookie,
  clearCookie,
  getBearerToken,
} = require('./lib/http');
const {
  nowIso,
  randomToken,
  hashToken,
  normalizeHandle,
  isValidHandle,
  createNovaAuthId,
  createNovaEmail,
  createPasswordRecord,
  verifyPassword,
  signJwt,
  verifyJwt,
  createCodeChallenge,
  createPkceVerifier,
} = require('./lib/security');

const AVAILABLE_SCOPES = Object.keys(SCOPE_DESCRIPTIONS);

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host}`);
  const pathname = requestUrl.pathname;
  const appUpdateMatch = pathname.match(/^\/api\/developer\/apps\/([^/]+)\/update$/);
  const appRotateSecretMatch = pathname.match(/^\/api\/developer\/apps\/([^/]+)\/rotate-secret$/);

  try {
    if (request.method === 'OPTIONS') {
      sendJson(response, 204, {});
      return;
    }

    if (request.method === 'GET' && pathname === '/authorize') {
      redirect(response, `${PORTAL_ORIGIN}/authorize${requestUrl.search}`);
      return;
    }

    if (request.method === 'GET' && pathname === '/.well-known/openid-configuration') {
      sendJson(response, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/api/sso/token`,
        userinfo_endpoint: `${ISSUER}/api/sso/userinfo`,
        introspection_endpoint: `${ISSUER}/api/sso/introspect`,
        revocation_endpoint: `${ISSUER}/api/sso/revoke`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: AVAILABLE_SCOPES,
        claims_supported: [
          'sub',
          'email',
          'nova_email',
          'name',
          'preferred_username',
          'nova_auth_id',
          'sid',
        ],
      });
      return;
    }

    if (request.method === 'GET' && pathname === '/.well-known/jwks.json') {
      sendJson(response, 200, getJwks());
      return;
    }

    if (request.method === 'GET' && pathname === '/api/health') {
      sendJson(response, 200, {
        ok: true,
        service: 'NovaAuth',
        issuer: ISSUER,
        portalOrigin: PORTAL_ORIGIN,
        clientOrigin: CLIENT_ORIGIN,
      });
      return;
    }

    if (request.method === 'GET' && pathname === '/api/sso/apps') {
      sendJson(response, 200, {
        issuer: ISSUER,
        authorizationEndpoint: `${ISSUER}/authorize`,
        tokenEndpoint: `${ISSUER}/api/sso/token`,
        userinfoEndpoint: `${ISSUER}/api/sso/userinfo`,
        introspectionEndpoint: `${ISSUER}/api/sso/introspect`,
        revocationEndpoint: `${ISSUER}/api/sso/revoke`,
        discoveryEndpoint: `${ISSUER}/.well-known/openid-configuration`,
        jwksUri: `${ISSUER}/.well-known/jwks.json`,
        scopes: AVAILABLE_SCOPES.map((scope) => ({
          key: scope,
          description: SCOPE_DESCRIPTIONS[scope],
        })),
        clients: listPublicClients(),
      });
      return;
    }

    if (request.method === 'GET' && pathname === '/api/auth/handle-availability') {
      handleCheckAvailability(requestUrl, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/auth/register') {
      await handleRegister(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/auth/login') {
      await handleLogin(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/auth/session') {
      handleSession(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/auth/logout') {
      handleLogout(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/notifications') {
      handleNotifications(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/notifications/read') {
      await handleNotificationsRead(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/account/settings') {
      handleAccountSettings(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/account/settings') {
      await handleAccountSettingsSave(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/account/connected-apps') {
      handleConnectedApps(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/account/connected-apps/revoke') {
      await handleRevokeConnectedApp(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/developer/apps') {
      handleDeveloperApps(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/developer/apps') {
      await handleCreateDeveloperApp(request, response);
      return;
    }

    if (request.method === 'POST' && appUpdateMatch) {
      await handleUpdateDeveloperApp(request, response, decodeURIComponent(appUpdateMatch[1]));
      return;
    }

    if (request.method === 'POST' && appRotateSecretMatch) {
      await handleRotateDeveloperSecret(request, response, decodeURIComponent(appRotateSecretMatch[1]));
      return;
    }

    if (request.method === 'GET' && pathname === '/api/sso/authorize/context') {
      handleAuthorizeContext(request, requestUrl, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/sso/authorize') {
      await handleAuthorize(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/sso/token') {
      await handleToken(request, response);
      return;
    }

    if (request.method === 'GET' && pathname === '/api/sso/userinfo') {
      handleUserInfo(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/sso/introspect') {
      await handleIntrospect(request, response);
      return;
    }

    if (request.method === 'POST' && pathname === '/api/sso/revoke') {
      await handleRevoke(request, response);
      return;
    }

    sendJson(response, 404, { error: 'Route not found.' });
  } catch (error) {
    sendJson(response, 500, {
      error: error.message || 'Unexpected server error.',
    });
  }
});

function getStore() {
  return readStore();
}

function persistStore(store) {
  writeStore(store);
}

function cleanupExpiredArtifacts(store) {
  const now = Date.now();
  store.sessions = store.sessions.filter((session) => {
    return !session.revokedAt && new Date(session.expiresAt).getTime() > now;
  });
  store.refreshTokens = store.refreshTokens.filter((token) => {
    return !token.revokedAt && new Date(token.expiresAt).getTime() > now;
  });
  store.authCodes = store.authCodes.filter((code) => {
    return !code.usedAt && new Date(code.expiresAt).getTime() > now;
  });
}

function sanitizeUser(user) {
  return {
    id: user.id,
    displayName: user.displayName,
    handle: user.handle,
    novaAuthId: user.novaAuthId,
    novaEmail: user.novaEmail,
    createdAt: user.createdAt,
    settings: normalizeUserSettings(user.settings),
  };
}

function getSessionBundle(request, store) {
  const cookies = parseCookies(request.headers.cookie || '');
  const sessionToken = cookies[SESSION_COOKIE_NAME];

  if (!sessionToken) {
    return null;
  }

  const sessionTokenHash = hashToken(sessionToken);
  const session = store.sessions.find((item) => item.tokenHash === sessionTokenHash);

  if (!session) {
    return null;
  }

  if (session.revokedAt || new Date(session.expiresAt).getTime() <= Date.now()) {
    return null;
  }

  const user = store.users.find((item) => item.id === session.userId);

  if (!user) {
    return null;
  }

  return {
    session,
    user,
    token: sessionToken,
  };
}

function requireSession(request, response, store) {
  const sessionBundle = getSessionBundle(request, store);

  if (!sessionBundle) {
    sendJson(response, 401, { error: 'Session not found or expired.' });
    return null;
  }

  return sessionBundle;
}

function createSession(store, userId) {
  const token = randomToken(48);
  const session = {
    id: randomToken(12),
    userId,
    tokenHash: hashToken(token),
    createdAt: nowIso(),
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  };

  store.sessions.push(session);
  return {
    token,
    session,
  };
}

function setSessionCookie(response, token) {
  setCookie(response, SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
    path: '/',
    sameSite: 'Lax',
  });
}

function clearSessionCookie(response) {
  clearCookie(response, SESSION_COOKIE_NAME, {
    httpOnly: true,
    path: '/',
    sameSite: 'Lax',
  });
}

function findUserByLogin(store, login) {
  const normalizedLogin = String(login || '').trim().toLowerCase();
  return store.users.find((user) => {
    return (
      (user.novaEmail && user.novaEmail.toLowerCase() === normalizedLogin) ||
      user.handle.toLowerCase() === normalizedLogin ||
      user.novaAuthId.toLowerCase() === normalizedLogin
    );
  });
}

function listUserNotifications(store, userId) {
  return store.notifications
    .filter((notification) => notification.userId === userId)
    .sort((left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime());
}

function pushNotification(store, notification) {
  store.notifications.push({
    id: randomToken(10),
    createdAt: nowIso(),
    readAt: null,
    ...notification,
  });
}

function ensureUniqueHandle(store, preferredHandle) {
  const baseHandle = normalizeHandle(preferredHandle);

  if (!isValidHandle(baseHandle)) {
    return null;
  }

  if (!store.users.some((user) => user.handle === baseHandle)) {
    return baseHandle;
  }

  for (let index = 1; index < 10000; index += 1) {
    const suffix = String(index);
    const trimmedBase = baseHandle.slice(0, 20 - suffix.length);
    const nextHandle = `${trimmedBase}${suffix}`;

    if (!store.users.some((user) => user.handle === nextHandle)) {
      return nextHandle;
    }
  }

  return null;
}

function buildHandleSuggestion(store, seed) {
  const cleanedSeed = normalizeHandle(seed).slice(0, 20);
  const seededHandle = cleanedSeed && /^[a-z]/.test(cleanedSeed) ? cleanedSeed : 'novauser';
  return ensureUniqueHandle(store, seededHandle);
}

function getScopeDescriptions(scopes) {
  return scopes.map((scope) => ({
    scope,
    description: SCOPE_DESCRIPTIONS[scope] || 'Custom NovaAuth scope.',
  }));
}

function parseScope(scopeInput, client) {
  const requestedScopes = String(scopeInput || client.defaultScopes.join(' '))
    .split(/\s+/)
    .filter(Boolean);
  const uniqueScopes = [...new Set(requestedScopes)];

  if (!uniqueScopes.every((scope) => client.allowedScopes.includes(scope))) {
    throw new Error('One or more requested scopes are not allowed for this client.');
  }

  if (!uniqueScopes.includes('openid')) {
    uniqueScopes.unshift('openid');
  }

  return uniqueScopes;
}

function validateAuthorizeParams(params) {
  const clientId = String(params.client_id || '').trim();
  const redirectUri = String(params.redirect_uri || '').trim();
  const state = String(params.state || '').trim();
  const responseType = String(params.response_type || 'code').trim();
  const codeChallenge = String(params.code_challenge || '').trim();
  const codeChallengeMethod = String(params.code_challenge_method || '').trim() || 'S256';
  const nonce = String(params.nonce || '').trim();
  const prompt = String(params.prompt || '').trim();

  if (!clientId || !redirectUri) {
    throw new Error('client_id and redirect_uri are required.');
  }

  if (responseType !== 'code') {
    throw new Error('Only response_type=code is supported.');
  }

  const client = getClientById(clientId);

  if (!client || client.status !== 'active') {
    throw new Error('Unknown client application.');
  }

  if (!client.redirectUris.includes(redirectUri)) {
    throw new Error('redirect_uri is not registered for this client.');
  }

  if (!codeChallenge || codeChallengeMethod !== 'S256') {
    throw new Error('PKCE is required with code_challenge_method=S256.');
  }

  const scopes = parseScope(params.scope, client);

  return {
    client,
    redirectUri,
    state,
    scopes,
    codeChallenge,
    codeChallengeMethod,
    nonce,
    prompt,
  };
}

function buildRedirectUri(baseUrl, params) {
  const target = new URL(baseUrl);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      target.searchParams.set(key, value);
    }
  });
  return target.toString();
}

function issueAuthCode(store, payload) {
  const rawCode = randomToken(32);
  const authCode = {
    id: randomToken(12),
    codeHash: hashToken(rawCode),
    userId: payload.userId,
    sessionId: payload.sessionId,
    clientId: payload.clientId,
    redirectUri: payload.redirectUri,
    scopes: payload.scopes,
    nonce: payload.nonce,
    codeChallenge: payload.codeChallenge,
    codeChallengeMethod: payload.codeChallengeMethod,
    createdAt: nowIso(),
    expiresAt: new Date(Date.now() + AUTH_CODE_TTL_MS).toISOString(),
    usedAt: null,
  };

  store.authCodes.push(authCode);
  return rawCode;
}

function createGrant(store, userId, clientId, scopes) {
  const existingGrant = store.grants.find((grant) => {
    return grant.userId === userId && grant.clientId === clientId;
  });

  if (existingGrant) {
    existingGrant.scopes = [...new Set([...existingGrant.scopes, ...scopes])];
    existingGrant.lastUsedAt = nowIso();
    return existingGrant;
  }

  const nextGrant = {
    id: randomToken(12),
    userId,
    clientId,
    scopes,
    createdAt: nowIso(),
    lastUsedAt: nowIso(),
  };
  store.grants.push(nextGrant);
  return nextGrant;
}

function issueTokens(store, client, user, session, scopes, nonce) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const accessExp = issuedAt + ACCESS_TOKEN_TTL_SECONDS;
  const commonClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: client.clientId,
    iat: issuedAt,
    nbf: issuedAt,
    sid: session.id,
    scope: scopes.join(' '),
    client_id: client.clientId,
  };

  const accessToken = signJwt({
    ...commonClaims,
    exp: accessExp,
    token_use: 'access',
    preferred_username: user.handle,
    nova_auth_id: user.novaAuthId,
  });

  const idToken = signJwt({
    ...commonClaims,
    exp: accessExp,
    token_use: 'id',
    nonce,
    email: user.novaEmail,
    nova_email: user.novaEmail,
    email_verified: true,
    name: user.displayName,
    preferred_username: user.handle,
    nova_auth_id: user.novaAuthId,
  });

  const refreshTokenValue = randomToken(48);
  const refreshToken = {
    id: randomToken(12),
    tokenHash: hashToken(refreshTokenValue),
    userId: user.id,
    sessionId: session.id,
    clientId: client.clientId,
    scopes,
    createdAt: nowIso(),
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS).toISOString(),
    revokedAt: null,
    rotatedFrom: null,
  };

  store.refreshTokens.push(refreshToken);

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshTokenValue,
    id_token: idToken,
    scope: scopes.join(' '),
  };
}

function verifyClientCredentials(clientId, clientSecret) {
  const client = getClientById(clientId);

  if (!client || client.status !== 'active') {
    return null;
  }

  if (client.clientType === 'confidential') {
    if (!clientSecret || client.clientSecret !== clientSecret) {
      return null;
    }
  }

  return client;
}

function resolveTokenRecord(store, rawToken) {
  const hashed = hashToken(rawToken);
  const refreshToken = store.refreshTokens.find((item) => item.tokenHash === hashed);

  if (refreshToken) {
    const user = store.users.find((item) => item.id === refreshToken.userId);
    return {
      tokenType: 'refresh_token',
      active:
        !refreshToken.revokedAt &&
        new Date(refreshToken.expiresAt).getTime() > Date.now() &&
        Boolean(user),
      user,
      refreshToken,
    };
  }

  try {
    const payload = verifyJwt(rawToken);
    const session = store.sessions.find((item) => item.id === payload.sid);
    const user = store.users.find((item) => item.id === payload.sub);
    const active =
      payload.token_use === 'access' &&
      session &&
      !session.revokedAt &&
      new Date(session.expiresAt).getTime() > Date.now() &&
      Boolean(user);

    return {
      tokenType: 'access_token',
      active: Boolean(active),
      user,
      session,
      payload,
    };
  } catch (error) {
    return {
      tokenType: 'unknown',
      active: false,
    };
  }
}

function getConnectedApps(store, userId) {
  const clientsById = new Map(readClients().map((client) => [client.clientId, client]));

  return store.grants
    .filter((grant) => grant.userId === userId)
    .map((grant) => {
      const client = clientsById.get(grant.clientId);
      return {
        clientId: grant.clientId,
        clientName: client ? client.clientName : grant.clientId,
        description: client ? client.description : 'Unknown application',
        applicationUrl: client ? client.applicationUrl : '',
        logoText: client ? client.logoText : 'NA',
        scopes: grant.scopes,
        lastUsedAt: grant.lastUsedAt,
        createdAt: grant.createdAt,
      };
    })
    .sort((left, right) => new Date(right.lastUsedAt).getTime() - new Date(left.lastUsedAt).getTime());
}

function parseBoolean(value, fallback = false) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  return fallback;
}

function parseStringArray(input) {
  if (Array.isArray(input)) {
    return [...new Set(input.map((item) => String(item).trim()).filter(Boolean))];
  }

  if (typeof input === 'string') {
    return [
      ...new Set(
        input
          .split(/\n|,/)
          .map((item) => item.trim())
          .filter(Boolean),
      ),
    ];
  }

  return [];
}

function parseUrlList(input, fieldName) {
  const values = parseStringArray(input);

  if (!values.length) {
    throw new Error(`${fieldName} must include at least one URL.`);
  }

  return values.map((value) => {
    let url;
    try {
      url = new URL(value);
    } catch (error) {
      throw new Error(`${fieldName} contains an invalid URL.`);
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error(`${fieldName} URLs must use http or https.`);
    }

    return url.toString();
  });
}

function createClientIdFromName(clientName, existingClients) {
  const base = String(clientName || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 28) || 'nova-app';

  let candidate = base;
  let counter = 1;

  while (existingClients.some((client) => client.clientId === candidate)) {
    candidate = `${base.slice(0, Math.max(8, 28 - String(counter).length - 1))}-${counter}`;
    counter += 1;
  }

  return candidate;
}

function validateSettingsUpdate(body, user) {
  const current = normalizeUserSettings(user.settings || createDefaultUserSettings());
  const developerDefaultScopes = parseStringArray(
    body.developerDefaultScopes ?? current.developerDefaultScopes,
  ).filter((scope) => AVAILABLE_SCOPES.includes(scope));
  const nextSettings = normalizeUserSettings({
    ...current,
    themePreference: body.themePreference ?? current.themePreference,
    compactMode: parseBoolean(body.compactMode, current.compactMode),
    emailUpdates: parseBoolean(body.emailUpdates, current.emailUpdates),
    securityAlerts: parseBoolean(body.securityAlerts, current.securityAlerts),
    developerDefaultClientType:
      body.developerDefaultClientType ?? current.developerDefaultClientType,
    developerDefaultScopes:
      developerDefaultScopes.length ? developerDefaultScopes : current.developerDefaultScopes,
    startPage: body.startPage ?? current.startPage,
    profileTagline: body.profileTagline ?? current.profileTagline,
  });

  return nextSettings;
}

function validateDeveloperAppInput(body, existingClients, existingClient) {
  const clientName = String(body.clientName || '').trim();
  const description = String(body.description || '').trim();
  const clientType = body.clientType === 'confidential' ? 'confidential' : 'public';
  const redirectUris = parseUrlList(body.redirectUris, 'Redirect URIs');
  const applicationUrl = String(body.applicationUrl || redirectUris[0]).trim();
  const allowedOriginsInput = parseStringArray(body.allowedOrigins);
  const allowedOrigins = allowedOriginsInput.length
    ? allowedOriginsInput.map((origin) => {
        let url;
        try {
          url = new URL(origin);
        } catch (error) {
          throw new Error('Allowed origins contains an invalid URL.');
        }
        return url.origin;
      })
    : [...new Set(redirectUris.map((uri) => new URL(uri).origin))];
  const allowedScopes = parseStringArray(body.allowedScopes).filter((scope) => AVAILABLE_SCOPES.includes(scope));
  const defaultScopes = parseStringArray(body.defaultScopes).filter((scope) => allowedScopes.includes(scope));
  const logoText = String(body.logoText || clientName.slice(0, 2) || 'NA')
    .replace(/[^a-z0-9]/gi, '')
    .slice(0, 3)
    .toUpperCase();

  if (!clientName) {
    throw new Error('Client name is required.');
  }

  if (!allowedScopes.includes('openid')) {
    allowedScopes.unshift('openid');
  }

  if (!defaultScopes.includes('openid')) {
    defaultScopes.unshift('openid');
  }

  let appUrl;
  try {
    appUrl = new URL(applicationUrl);
  } catch (error) {
    throw new Error('Application URL must be a valid URL.');
  }

  const now = nowIso();
  return {
    clientId:
      existingClient?.clientId || createClientIdFromName(clientName, existingClients),
    clientName,
    description,
    clientType,
    clientSecret:
      clientType === 'confidential'
        ? existingClient?.clientSecret || createClientSecret()
        : '',
    redirectUris,
    allowedOrigins: [...new Set(allowedOrigins)],
    applicationUrl: appUrl.toString(),
    defaultScopes: [...new Set(defaultScopes)],
    allowedScopes: [...new Set(allowedScopes)],
    logoText: logoText || 'NA',
    status: body.status === 'disabled' ? 'disabled' : 'active',
    ownerUserId: existingClient?.ownerUserId || null,
    createdAt: existingClient?.createdAt || now,
    updatedAt: now,
  };
}

function getOwnedClient(clients, clientId, ownerUserId) {
  return clients.find((client) => client.clientId === clientId && client.ownerUserId === ownerUserId) || null;
}

function handleCheckAvailability(requestUrl, response) {
  const store = getStore();
  const handle = normalizeHandle(requestUrl.searchParams.get('handle'));
  const suggestionSeed = requestUrl.searchParams.get('seed') || handle;

  if (!handle) {
    const suggestion = buildHandleSuggestion(store, suggestionSeed);
    sendJson(response, 200, {
      available: false,
      suggestion,
      novaAuthId: suggestion ? createNovaAuthId(suggestion) : null,
      message: 'Provide a handle to check availability.',
    });
    return;
  }

  if (!isValidHandle(handle)) {
    const suggestion = buildHandleSuggestion(store, suggestionSeed);
    sendJson(response, 200, {
      available: false,
      suggestion,
      novaAuthId: suggestion ? createNovaAuthId(suggestion) : null,
      message: 'Handle must start with a letter and be 3-20 characters using letters, numbers, or underscores.',
    });
    return;
  }

  const available = !store.users.some((user) => user.handle === handle);
  const suggestion = available ? handle : ensureUniqueHandle(store, handle);

  sendJson(response, 200, {
    available,
    suggestion,
    novaAuthId: suggestion ? createNovaAuthId(suggestion) : null,
    message: available ? 'Handle is available.' : 'Handle is already taken.',
  });
}

async function handleRegister(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const body = await parseBody(request);
  const displayName = String(body.displayName || '').trim();
  const password = String(body.password || '');
  const rawHandle = body.desiredHandle || displayName;
  const handle = normalizeHandle(rawHandle);

  if (!displayName || !password) {
    sendJson(response, 400, { error: 'Display name and password are required.' });
    return;
  }

  if (password.length < 8) {
    sendJson(response, 400, { error: 'Password must be at least 8 characters long.' });
    return;
  }

  if (!isValidHandle(handle)) {
    sendJson(response, 400, {
      error: 'Handle must start with a letter and be 3-20 characters using letters, numbers, or underscores.',
    });
    return;
  }

  if (store.users.some((user) => user.handle === handle)) {
    sendJson(response, 409, {
      error: 'That NovaAuth handle is already taken.',
      suggestion: ensureUniqueHandle(store, handle),
    });
    return;
  }

  const passwordRecord = createPasswordRecord(password);
  const user = {
    id: randomToken(12),
    displayName,
    handle,
    novaAuthId: createNovaAuthId(handle),
    novaEmail: createNovaEmail(handle),
    passwordHash: passwordRecord.hash,
    passwordSalt: passwordRecord.salt,
    createdAt: nowIso(),
    settings: createDefaultUserSettings(),
  };

  store.users.push(user);
  pushNotification(store, {
    userId: user.id,
    type: 'welcome',
    title: 'Welcome to NovaAuth',
    body: `Your identity ${user.novaAuthId} is now active.`,
  });
  pushNotification(store, {
    userId: user.id,
    type: 'mailbox',
    title: 'Nova mailbox created',
    body: `Your built-in NovaAuth address is ${user.novaEmail}.`,
  });
  const { token, session } = createSession(store, user.id);
  persistStore(store);
  setSessionCookie(response, token);

  sendJson(response, 201, {
    authenticated: true,
    session: {
      id: session.id,
      expiresAt: session.expiresAt,
    },
    user: sanitizeUser(user),
  });
}

async function handleLogin(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const body = await parseBody(request);
  const login = String(body.login || '').trim();
  const password = String(body.password || '');

  if (!login || !password) {
    sendJson(response, 400, { error: 'Login and password are required.' });
    return;
  }

  const user = findUserByLogin(store, login);

  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    sendJson(response, 401, { error: 'Invalid NovaAuth mailbox, handle, NovaAuth ID, or password.' });
    return;
  }

  const { token, session } = createSession(store, user.id);
  persistStore(store);
  setSessionCookie(response, token);

  sendJson(response, 200, {
    authenticated: true,
    session: {
      id: session.id,
      expiresAt: session.expiresAt,
    },
    user: sanitizeUser(user),
  });
}

function handleSession(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = getSessionBundle(request, store);
  persistStore(store);

  if (!sessionBundle) {
    sendJson(response, 401, { authenticated: false, error: 'Session not found or expired.' });
    return;
  }

  sendJson(response, 200, {
    authenticated: true,
    session: {
      id: sessionBundle.session.id,
      expiresAt: sessionBundle.session.expiresAt,
    },
    user: sanitizeUser(sessionBundle.user),
    inbox: {
      unreadCount: listUserNotifications(store, sessionBundle.user.id).filter((item) => !item.readAt).length,
    },
    connectedApps: {
      count: getConnectedApps(store, sessionBundle.user.id).length,
    },
  });
}

function handleNotifications(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const notifications = listUserNotifications(store, sessionBundle.user.id);
  persistStore(store);

  sendJson(response, 200, {
    notifications,
    unreadCount: notifications.filter((item) => !item.readAt).length,
  });
}

async function handleNotificationsRead(request, response) {
  const store = getStore();
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const body = await parseBody(request);
  const ids = Array.isArray(body.ids) ? body.ids.map((item) => String(item)) : [];
  const markAll = Boolean(body.markAll);
  const readAt = nowIso();

  store.notifications = store.notifications.map((notification) => {
    const ownsNotification = notification.userId === sessionBundle.user.id;
    const shouldMark = markAll || ids.includes(notification.id);

    if (ownsNotification && shouldMark && !notification.readAt) {
      return {
        ...notification,
        readAt,
      };
    }

    return notification;
  });

  persistStore(store);
  const notifications = listUserNotifications(store, sessionBundle.user.id);

  sendJson(response, 200, {
    ok: true,
    notifications,
    unreadCount: notifications.filter((item) => !item.readAt).length,
  });
}

function handleLogout(request, response) {
  const store = getStore();
  const sessionBundle = getSessionBundle(request, store);

  if (sessionBundle) {
    sessionBundle.session.revokedAt = nowIso();
    store.refreshTokens = store.refreshTokens.map((token) => {
      if (token.sessionId === sessionBundle.session.id && !token.revokedAt) {
        return {
          ...token,
          revokedAt: nowIso(),
        };
      }
      return token;
    });
  }

  persistStore(store);
  clearSessionCookie(response);

  sendJson(response, 200, { ok: true });
}

function handleAccountSettings(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  sendJson(response, 200, {
    settings: normalizeUserSettings(sessionBundle.user.settings),
    availableScopes: AVAILABLE_SCOPES.map((scope) => ({
      key: scope,
      description: SCOPE_DESCRIPTIONS[scope],
    })),
  });
}

async function handleAccountSettingsSave(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const body = await parseBody(request);
  sessionBundle.user.settings = validateSettingsUpdate(body, sessionBundle.user);
  persistStore(store);

  sendJson(response, 200, {
    ok: true,
    settings: normalizeUserSettings(sessionBundle.user.settings),
    user: sanitizeUser(sessionBundle.user),
  });
}

function handleConnectedApps(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  sendJson(response, 200, {
    apps: getConnectedApps(store, sessionBundle.user.id),
  });
}

async function handleRevokeConnectedApp(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const body = await parseBody(request);
  const clientId = String(body.clientId || '').trim();

  if (!clientId) {
    sendJson(response, 400, { error: 'clientId is required.' });
    return;
  }

  store.grants = store.grants.filter((grant) => {
    return !(grant.userId === sessionBundle.user.id && grant.clientId === clientId);
  });
  store.refreshTokens = store.refreshTokens.map((token) => {
    if (token.userId === sessionBundle.user.id && token.clientId === clientId && !token.revokedAt) {
      return {
        ...token,
        revokedAt: nowIso(),
      };
    }
    return token;
  });
  persistStore(store);

  sendJson(response, 200, {
    ok: true,
    apps: getConnectedApps(store, sessionBundle.user.id),
  });
}

function handleDeveloperApps(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const clients = readClients().filter((client) => client.ownerUserId === sessionBundle.user.id);

  sendJson(response, 200, {
    apps: clients.map((client) => ({
      ...toPublicClient(client),
      hasClientSecret: client.clientType === 'confidential',
      clientSecretPreview: client.clientSecret ? `${client.clientSecret.slice(0, 6)}...` : null,
    })),
    defaults: normalizeUserSettings(sessionBundle.user.settings),
    scopes: AVAILABLE_SCOPES.map((scope) => ({
      key: scope,
      description: SCOPE_DESCRIPTIONS[scope],
    })),
  });
}

async function handleCreateDeveloperApp(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const body = await parseBody(request);
  const clients = readClients();
  const payload = validateDeveloperAppInput(body, clients);
  const nextClient = {
    ...payload,
    ownerUserId: sessionBundle.user.id,
  };
  clients.push(nextClient);
  writeClients(clients);
  pushNotification(store, {
    userId: sessionBundle.user.id,
    type: 'developer',
    title: 'OAuth client created',
    body: `Your app ${nextClient.clientName} is ready to use Sign in with NovaAuth.`,
  });
  persistStore(store);

  sendJson(response, 201, {
    ok: true,
    app: {
      ...toPublicClient(nextClient),
      hasClientSecret: nextClient.clientType === 'confidential',
      clientSecret: nextClient.clientType === 'confidential' ? nextClient.clientSecret : null,
    },
  });
}

async function handleUpdateDeveloperApp(request, response, clientId) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const body = await parseBody(request);
  const clients = readClients();
  const existingClient = getOwnedClient(clients, clientId, sessionBundle.user.id);

  if (!existingClient) {
    sendJson(response, 404, { error: 'Developer app not found.' });
    return;
  }

  const nextClient = validateDeveloperAppInput(body, clients, existingClient);
  const updatedClients = clients.map((client) => (client.clientId === existingClient.clientId ? nextClient : client));
  writeClients(updatedClients);

  sendJson(response, 200, {
    ok: true,
    app: {
      ...toPublicClient(nextClient),
      hasClientSecret: nextClient.clientType === 'confidential',
      clientSecretPreview: nextClient.clientSecret ? `${nextClient.clientSecret.slice(0, 6)}...` : null,
    },
  });
}

async function handleRotateDeveloperSecret(request, response, clientId) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = requireSession(request, response, store);

  if (!sessionBundle) {
    return;
  }

  const clients = readClients();
  const existingClient = getOwnedClient(clients, clientId, sessionBundle.user.id);

  if (!existingClient) {
    sendJson(response, 404, { error: 'Developer app not found.' });
    return;
  }

  if (existingClient.clientType !== 'confidential') {
    sendJson(response, 400, { error: 'Public clients do not use a client secret.' });
    return;
  }

  existingClient.clientSecret = createClientSecret();
  existingClient.updatedAt = nowIso();
  writeClients(clients);
  store.refreshTokens = store.refreshTokens.map((token) => {
    if (token.clientId === existingClient.clientId && !token.revokedAt) {
      return {
        ...token,
        revokedAt: nowIso(),
      };
    }
    return token;
  });
  persistStore(store);

  sendJson(response, 200, {
    ok: true,
    clientId: existingClient.clientId,
    clientSecret: existingClient.clientSecret,
  });
}

function handleAuthorizeContext(request, requestUrl, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  persistStore(store);

  let parsed;
  try {
    parsed = validateAuthorizeParams(Object.fromEntries(requestUrl.searchParams.entries()));
  } catch (error) {
    sendJson(response, 400, { error: error.message });
    return;
  }

  const sessionBundle = getSessionBundle(request, store);
  const existingGrant = sessionBundle
    ? store.grants.find((grant) => {
        return grant.userId === sessionBundle.user.id && grant.clientId === parsed.client.clientId;
      })
    : null;
  const samplePkceVerifier = createPkceVerifier();

  if (parsed.prompt === 'none' && !sessionBundle) {
    sendJson(response, 401, {
      authenticated: false,
      requiresLogin: true,
      error: 'login_required',
    });
    return;
  }

  sendJson(response, 200, {
    authenticated: Boolean(sessionBundle),
    client: {
      clientId: parsed.client.clientId,
      clientName: parsed.client.clientName,
      description: parsed.client.description,
      redirectUri: parsed.redirectUri,
      applicationUrl: parsed.client.applicationUrl,
      logoText: parsed.client.logoText,
      clientType: parsed.client.clientType,
    },
    user: sessionBundle ? sanitizeUser(sessionBundle.user) : null,
    requestedScopes: getScopeDescriptions(parsed.scopes),
    priorGrant: existingGrant
      ? {
          scopes: existingGrant.scopes,
          lastUsedAt: existingGrant.lastUsedAt,
        }
      : null,
    prompt: parsed.prompt || null,
    samplePkceVerifier,
    sampleCodeChallenge: createCodeChallenge(samplePkceVerifier),
  });
}

async function handleAuthorize(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const sessionBundle = getSessionBundle(request, store);

  if (!sessionBundle) {
    clearSessionCookie(response);
    sendJson(response, 401, { error: 'You must sign in before authorizing an app.' });
    return;
  }

  const body = await parseBody(request);
  let parsed;
  try {
    parsed = validateAuthorizeParams(body);
  } catch (error) {
    sendJson(response, 400, { error: error.message });
    return;
  }

  if (body.approve === false) {
    sendJson(response, 200, {
      approved: false,
      redirectTo: buildRedirectUri(parsed.redirectUri, {
        error: 'access_denied',
        state: parsed.state,
      }),
    });
    return;
  }

  createGrant(store, sessionBundle.user.id, parsed.client.clientId, parsed.scopes);
  const code = issueAuthCode(store, {
    userId: sessionBundle.user.id,
    sessionId: sessionBundle.session.id,
    clientId: parsed.client.clientId,
    redirectUri: parsed.redirectUri,
    scopes: parsed.scopes,
    nonce: parsed.nonce,
    codeChallenge: parsed.codeChallenge,
    codeChallengeMethod: parsed.codeChallengeMethod,
  });

  persistStore(store);

  sendJson(response, 200, {
    approved: true,
    redirectTo: buildRedirectUri(parsed.redirectUri, {
      code,
      state: parsed.state,
    }),
  });
}

async function handleToken(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const body = await parseBody(request);
  const grantType = String(body.grant_type || '').trim();
  const clientId = String(body.client_id || '').trim();
  const clientSecret = String(body.client_secret || '').trim();
  const client = verifyClientCredentials(clientId, clientSecret);

  if (!grantType || !client) {
    sendJson(response, 401, { error: 'Invalid client credentials or grant type.' });
    return;
  }

  if (grantType === 'authorization_code') {
    const code = String(body.code || '').trim();
    const redirectUri = String(body.redirect_uri || '').trim();
    const codeVerifier = String(body.code_verifier || '').trim();

    if (!code || !redirectUri || !codeVerifier) {
      sendJson(response, 400, { error: 'code, redirect_uri, and code_verifier are required.' });
      return;
    }

    const codeHash = hashToken(code);
    const authCode = store.authCodes.find((item) => item.codeHash === codeHash);

    if (!authCode || authCode.usedAt) {
      sendJson(response, 400, { error: 'Authorization code is invalid or already used.' });
      return;
    }

    if (new Date(authCode.expiresAt).getTime() <= Date.now()) {
      sendJson(response, 400, { error: 'Authorization code has expired.' });
      return;
    }

    if (authCode.clientId !== client.clientId || authCode.redirectUri !== redirectUri) {
      sendJson(response, 400, { error: 'Authorization code does not match the client or redirect URI.' });
      return;
    }

    if (createCodeChallenge(codeVerifier) !== authCode.codeChallenge) {
      sendJson(response, 400, { error: 'PKCE verification failed.' });
      return;
    }

    const user = store.users.find((item) => item.id === authCode.userId);
    const session = store.sessions.find((item) => item.id === authCode.sessionId);

    if (!user || !session || session.revokedAt || new Date(session.expiresAt).getTime() <= Date.now()) {
      sendJson(response, 400, { error: 'The login session for this code is no longer active.' });
      return;
    }

    authCode.usedAt = nowIso();
    const tokens = issueTokens(store, client, user, session, authCode.scopes, authCode.nonce);
    persistStore(store);

    sendJson(response, 200, tokens);
    return;
  }

  if (grantType === 'refresh_token') {
    const rawRefreshToken = String(body.refresh_token || '').trim();

    if (!rawRefreshToken) {
      sendJson(response, 400, { error: 'refresh_token is required.' });
      return;
    }

    const tokenHash = hashToken(rawRefreshToken);
    const refreshToken = store.refreshTokens.find((item) => item.tokenHash === tokenHash);

    if (!refreshToken || refreshToken.revokedAt) {
      sendJson(response, 400, { error: 'Refresh token is invalid or revoked.' });
      return;
    }

    if (new Date(refreshToken.expiresAt).getTime() <= Date.now()) {
      sendJson(response, 400, { error: 'Refresh token has expired.' });
      return;
    }

    if (refreshToken.clientId !== client.clientId) {
      sendJson(response, 400, { error: 'Refresh token was not issued to this client.' });
      return;
    }

    const user = store.users.find((item) => item.id === refreshToken.userId);
    const session = store.sessions.find((item) => item.id === refreshToken.sessionId);

    if (!user || !session || session.revokedAt || new Date(session.expiresAt).getTime() <= Date.now()) {
      sendJson(response, 400, { error: 'The parent login session is no longer active.' });
      return;
    }

    refreshToken.revokedAt = nowIso();
    const tokens = issueTokens(store, client, user, session, refreshToken.scopes, '');
    const newestRefreshToken = store.refreshTokens[store.refreshTokens.length - 1];
    newestRefreshToken.rotatedFrom = refreshToken.id;
    persistStore(store);

    sendJson(response, 200, tokens);
    return;
  }

  sendJson(response, 400, { error: 'Unsupported grant_type.' });
}

function handleUserInfo(request, response) {
  const rawToken = getBearerToken(request.headers.authorization || '');

  if (!rawToken) {
    sendJson(response, 401, { error: 'Bearer access token is required.' });
    return;
  }

  const store = getStore();
  const tokenRecord = resolveTokenRecord(store, rawToken);

  if (!tokenRecord.active || tokenRecord.tokenType !== 'access_token') {
    sendJson(response, 401, { error: 'Access token is invalid or expired.' });
    return;
  }

  sendJson(response, 200, {
    sub: tokenRecord.user.id,
    email: tokenRecord.user.novaEmail,
    nova_email: tokenRecord.user.novaEmail,
    email_verified: true,
    name: tokenRecord.user.displayName,
    preferred_username: tokenRecord.user.handle,
    nova_auth_id: tokenRecord.user.novaAuthId,
    sid: tokenRecord.session.id,
  });
}

async function handleIntrospect(request, response) {
  const store = getStore();
  cleanupExpiredArtifacts(store);
  const body = await parseBody(request);
  const clientId = String(body.client_id || '').trim();
  const clientSecret = String(body.client_secret || '').trim();
  const token = String(body.token || '').trim();
  const client = verifyClientCredentials(clientId, clientSecret);

  if (!client || !token) {
    sendJson(response, 401, { active: false, error: 'Valid client credentials and token are required.' });
    return;
  }

  const tokenRecord = resolveTokenRecord(store, token);

  if (!tokenRecord.active) {
    sendJson(response, 200, { active: false });
    return;
  }

  if (tokenRecord.tokenType === 'refresh_token') {
    sendJson(response, 200, {
      active: true,
      token_type: 'refresh_token',
      client_id: tokenRecord.refreshToken.clientId,
      sub: tokenRecord.user.id,
      scope: tokenRecord.refreshToken.scopes.join(' '),
      exp: Math.floor(new Date(tokenRecord.refreshToken.expiresAt).getTime() / 1000),
    });
    return;
  }

  sendJson(response, 200, {
    active: true,
    token_type: 'access_token',
    client_id: tokenRecord.payload.client_id,
    sub: tokenRecord.payload.sub,
    scope: tokenRecord.payload.scope,
    exp: tokenRecord.payload.exp,
    sid: tokenRecord.payload.sid,
    novaauth_id: tokenRecord.user.novaAuthId,
  });
}

async function handleRevoke(request, response) {
  const store = getStore();
  const body = await parseBody(request);
  const clientId = String(body.client_id || '').trim();
  const clientSecret = String(body.client_secret || '').trim();
  const token = String(body.token || '').trim();
  const client = verifyClientCredentials(clientId, clientSecret);

  if (!client || !token) {
    sendJson(response, 401, { error: 'Valid client credentials and token are required.' });
    return;
  }

  const tokenHash = hashToken(token);
  const refreshToken = store.refreshTokens.find((item) => item.tokenHash === tokenHash);

  if (refreshToken && refreshToken.clientId === client.clientId) {
    refreshToken.revokedAt = nowIso();
    persistStore(store);
  }

  sendJson(response, 200, { revoked: true });
}

server.listen(PORT, () => {
  console.log(`NovaAuth SSO server running on ${ISSUER}`);
});
