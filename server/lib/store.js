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
  readStore,
  writeStore,
};
