const { CLIENT_ORIGIN } = require('./config');

function getCorsOrigin(requestOrigin) {
  if (!requestOrigin) {
    return CLIENT_ORIGIN;
  }

  return requestOrigin;
}

function sendJson(response, statusCode, payload, requestOrigin) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': getCorsOrigin(requestOrigin),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  response.end(JSON.stringify(payload));
}

function redirect(response, location) {
  response.writeHead(302, { Location: location });
  response.end();
}

function parseUrlEncoded(body) {
  const params = new URLSearchParams(body);
  return Object.fromEntries(params.entries());
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';

    request.on('data', (chunk) => {
      body += chunk;
    });

    request.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }

      const contentType = request.headers['content-type'] || '';

      try {
        if (contentType.includes('application/json')) {
          resolve(JSON.parse(body));
          return;
        }

        if (contentType.includes('application/x-www-form-urlencoded')) {
          resolve(parseUrlEncoded(body));
          return;
        }

        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error('Invalid request payload.'));
      }
    });

    request.on('error', reject);
  });
}

function parseCookies(cookieHeader) {
  return String(cookieHeader || '')
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce((accumulator, pair) => {
      const [name, ...valueParts] = pair.split('=');
      accumulator[name] = decodeURIComponent(valueParts.join('='));
      return accumulator;
    }, {});
}

function buildCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  if (options.httpOnly) {
    parts.push('HttpOnly');
  }

  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }

  if (options.path) {
    parts.push(`Path=${options.path}`);
  }

  return parts.join('; ');
}

function setCookie(response, name, value, options = {}) {
  const existing = response.getHeader('Set-Cookie');
  const cookies = Array.isArray(existing) ? existing : existing ? [existing] : [];
  response.setHeader('Set-Cookie', [...cookies, buildCookie(name, value, options)]);
}

function clearCookie(response, name, options = {}) {
  setCookie(response, name, '', {
    ...options,
    maxAge: 0,
  });
}

function getBearerToken(authorizationHeader) {
  const [, token] = String(authorizationHeader || '').match(/^Bearer\s+(.+)$/i) || [];
  return token || null;
}

module.exports = {
  sendJson,
  redirect,
  parseBody,
  parseCookies,
  setCookie,
  clearCookie,
  getBearerToken,
};
