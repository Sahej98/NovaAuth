const crypto = require('crypto');
const { getSigningKey } = require('./config');

function nowIso() {
  return new Date().toISOString();
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(input) {
  const normalized = String(input)
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(String(input).length / 4) * 4, '=');
  return Buffer.from(normalized, 'base64').toString('utf8');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function normalizeHandle(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/[^a-z0-9_]/g, '');
}

function isValidHandle(handle) {
  return /^[a-z][a-z0-9_]{2,19}$/.test(handle);
}

function createNovaAuthId(handle) {
  return `${handle}#NovaAuth`;
}

function createNovaEmail(handle) {
  return `${handle}@novaauth.id`;
}

function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const actualHash = crypto.scryptSync(password, salt, 64).toString('hex');
  const expectedBuffer = Buffer.from(expectedHash, 'hex');
  const actualBuffer = Buffer.from(actualHash, 'hex');

  return (
    expectedBuffer.length === actualBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, actualBuffer)
  );
}

function createPkceVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function createCodeChallenge(verifier) {
  return base64UrlEncode(crypto.createHash('sha256').update(String(verifier)).digest());
}

function signJwt(payload) {
  const signingKey = getSigningKey();
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: signingKey.kid,
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const content = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(content), signingKey.privateKey);

  return `${content}.${base64UrlEncode(signature)}`;
}

function verifyJwt(token) {
  const parts = String(token || '').split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid JWT format.');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingKey = getSigningKey();
  const content = `${encodedHeader}.${encodedPayload}`;
  const signature = Buffer.from(
    String(encodedSignature)
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(encodedSignature.length / 4) * 4, '='),
    'base64',
  );

  const isValid = crypto.verify('RSA-SHA256', Buffer.from(content), signingKey.publicKey, signature);

  if (!isValid) {
    throw new Error('Invalid JWT signature.');
  }

  const header = JSON.parse(base64UrlDecode(encodedHeader));
  const payload = JSON.parse(base64UrlDecode(encodedPayload));

  if (header.alg !== 'RS256') {
    throw new Error('Unsupported signing algorithm.');
  }

  if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('Token has expired.');
  }

  return payload;
}

module.exports = {
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
};
