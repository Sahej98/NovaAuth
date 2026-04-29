const fs = require('fs');
const path = require('path');
const { createNovaEmail } = require('./security');

const DATA_DIR = path.join(__dirname, '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'auth-store.json');

function createEmptyStore() {
  return {
    users: [],
    sessions: [],
    refreshTokens: [],
    authCodes: [],
    grants: [],
    notifications: [],
  };
}

function createDefaultUserSettings() {
  return {
    themePreference: 'system',
    compactMode: false,
    emailUpdates: true,
    securityAlerts: true,
    developerDefaultClientType: 'public',
    developerDefaultScopes: ['openid', 'profile', 'email'],
    startPage: 'dashboard',
    profileTagline: '',
  };
}

function normalizeUserSettings(settings) {
  const nextSettings = {
    ...createDefaultUserSettings(),
    ...(settings || {}),
  };
  const themePreference = ['system', 'light', 'dark'].includes(nextSettings.themePreference)
    ? nextSettings.themePreference
    : 'system';
  const developerDefaultClientType =
    nextSettings.developerDefaultClientType === 'confidential' ? 'confidential' : 'public';
  const startPage = ['dashboard', 'apps', 'settings', 'docs'].includes(nextSettings.startPage)
    ? nextSettings.startPage
    : 'dashboard';
  const developerDefaultScopes = Array.isArray(nextSettings.developerDefaultScopes)
    ? [...new Set(nextSettings.developerDefaultScopes.map((scope) => String(scope).trim()).filter(Boolean))]
    : createDefaultUserSettings().developerDefaultScopes;

  return {
    ...nextSettings,
    themePreference,
    compactMode: Boolean(nextSettings.compactMode),
    emailUpdates: Boolean(nextSettings.emailUpdates),
    securityAlerts: Boolean(nextSettings.securityAlerts),
    developerDefaultClientType,
    developerDefaultScopes: developerDefaultScopes.length
      ? developerDefaultScopes
      : createDefaultUserSettings().developerDefaultScopes,
    startPage,
    profileTagline: String(nextSettings.profileTagline || '').trim().slice(0, 120),
  };
}

function ensureStoreFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(STORE_FILE)) {
    fs.writeFileSync(STORE_FILE, JSON.stringify(createEmptyStore(), null, 2));
  }
}

function normalizeStoreShape(store) {
  const nextStore = {
    ...createEmptyStore(),
    ...store,
  };

  nextStore.users = Array.isArray(nextStore.users) ? nextStore.users : [];
  nextStore.sessions = Array.isArray(nextStore.sessions) ? nextStore.sessions : [];
  nextStore.refreshTokens = Array.isArray(nextStore.refreshTokens) ? nextStore.refreshTokens : [];
  nextStore.authCodes = Array.isArray(nextStore.authCodes) ? nextStore.authCodes : [];
  nextStore.grants = Array.isArray(nextStore.grants) ? nextStore.grants : [];
  nextStore.notifications = Array.isArray(nextStore.notifications) ? nextStore.notifications : [];
  nextStore.users = nextStore.users.map((user) => ({
    ...user,
    novaEmail: user.novaEmail || createNovaEmail(user.handle),
    settings: normalizeUserSettings(user.settings),
  }));

  return nextStore;
}

function readStore() {
  ensureStoreFile();
  const raw = fs.readFileSync(STORE_FILE, 'utf8');
  return normalizeStoreShape(JSON.parse(raw));
}

function writeStore(store) {
  ensureStoreFile();
  fs.writeFileSync(STORE_FILE, JSON.stringify(normalizeStoreShape(store), null, 2));
}

module.exports = {
  createEmptyStore,
  createDefaultUserSettings,
  normalizeUserSettings,
  readStore,
  writeStore,
};
