const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 4000);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const PORTAL_ORIGIN = process.env.PORTAL_ORIGIN || CLIENT_ORIGIN;
const ISSUER = process.env.ISSUER || `http://localhost:${PORT}`;
const SESSION_COOKIE_NAME = 'novaauth_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const AUTH_CODE_TTL_MS = 1000 * 60 * 5;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 10;
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const NOVA_AUTH_SUFFIX = '#NovaAuth';

const CONFIG_DIR = path.join(__dirname, '..', 'config');
const CLIENTS_FILE = path.join(CONFIG_DIR, 'clients.json');
const DATA_DIR = path.join(__dirname, '..', 'data');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');

const SCOPE_DESCRIPTIONS = {
  openid: 'Basic OpenID Connect identity.',
  profile: 'Read the user display name, handle, and NovaAuth ID.',
  email: 'Read the user NovaAuth mailbox address.',
  'apps:read': 'Read connected app metadata for the user.',
  'notifications:read': 'Read NovaAuth inbox and system notifications.',
};

function ensureClientsFile() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }

  if (!fs.existsSync(CLIENTS_FILE)) {
    const starterClients = [
      {
        clientId: 'nova-notes-web',
        clientName: 'Nova Notes',
        description: 'A public SPA client using Authorization Code + PKCE.',
        clientType: 'public',
        redirectUris: ['http://localhost:4174/auth/callback'],
        allowedOrigins: ['http://localhost:4174'],
        applicationUrl: 'http://localhost:4174',
        defaultScopes: ['openid', 'profile', 'email'],
        allowedScopes: ['openid', 'profile', 'email'],
        logoText: 'NN',
      },
      {
        clientId: 'nova-admin-api',
        clientName: 'Nova Admin',
        description: 'A confidential backend-enabled app that can introspect and refresh securely.',
        clientType: 'confidential',
        clientSecret: 'replace-this-secret-before-production',
        redirectUris: ['http://localhost:3001/auth/callback'],
        allowedOrigins: ['http://localhost:3001'],
        applicationUrl: 'http://localhost:3001',
        defaultScopes: ['openid', 'profile', 'email', 'apps:read'],
        allowedScopes: ['openid', 'profile', 'email', 'apps:read'],
        logoText: 'NA',
      },
    ];

    fs.writeFileSync(CLIENTS_FILE, JSON.stringify(starterClients, null, 2));
  }
}

function readClients() {
  ensureClientsFile();
  return JSON.parse(fs.readFileSync(CLIENTS_FILE, 'utf8'));
}

function getClientById(clientId) {
  return readClients().find((client) => client.clientId === clientId) || null;
}

function listPublicClients() {
  return readClients().map((client) => ({
    clientId: client.clientId,
    clientName: client.clientName,
    description: client.description,
    clientType: client.clientType,
    applicationUrl: client.applicationUrl,
    redirectUris: client.redirectUris,
    allowedScopes: client.allowedScopes,
    logoText: client.logoText,
  }));
}

function ensureKeysFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(KEYS_FILE)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    const keyBundle = {
      kid: crypto.randomUUID(),
      publicKey,
      privateKey,
      createdAt: new Date().toISOString(),
    };

    fs.writeFileSync(KEYS_FILE, JSON.stringify(keyBundle, null, 2));
  }
}

function getSigningKey() {
  ensureKeysFile();
  return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

function getJwks() {
  const signingKey = getSigningKey();
  const jwk = crypto.createPublicKey(signingKey.publicKey).export({ format: 'jwk' });

  return {
    keys: [
      {
        ...jwk,
        use: 'sig',
        alg: 'RS256',
        kid: signingKey.kid,
      },
    ],
  };
}

module.exports = {
  PORT,
  CLIENT_ORIGIN,
  PORTAL_ORIGIN,
  ISSUER,
  SESSION_COOKIE_NAME,
  SESSION_TTL_MS,
  AUTH_CODE_TTL_MS,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_MS,
  NOVA_AUTH_SUFFIX,
  SCOPE_DESCRIPTIONS,
  getClientById,
  listPublicClients,
  getSigningKey,
  getJwks,
};
