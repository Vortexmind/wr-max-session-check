/**
 * index.ts — wr-max-session-check
 *
 * Enforces a hard wall-clock session limit on top of a Cloudflare Waiting Room.
 *
 * Execution order on Cloudflare edge:
 *   DDoS / WAF / Bot Mgmt → Waiting Room → [this Worker] → Origin
 *
 * This Worker only sees requests that the Waiting Room has already admitted.
 * It does not enforce a concurrency cap; it only ensures that no user can
 * remain in the application beyond MAX_SESSION_MS, regardless of whether the
 * Waiting Room keeps auto-renewing their session.
 *
 * Required environment variables / secrets:
 *   HMAC_SECRET    (secret) Random 32+ byte string for cookie signing.
 *                           Generate: openssl rand -base64 32
 *                           Set via:  wrangler secret put HMAC_SECRET
 *   MAX_SESSION_MS (var)    Hard session lifetime in ms. Default: 3600000 (1h).
 *   SESSION_COOKIE (var)    Cookie name. Default: "app_session".
 */

import {
  signCookie,
  verifyCookie,
  getCookieValue,
  buildSetCookieHeader,
  buildClearCookieHeader,
  newSessionId,
} from './cookie';

export interface Env {
  HMAC_SECRET: string;
  MAX_SESSION_MS?: string;
  SESSION_COOKIE?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WR_REVOKE_HEADER = 'Cf-Waiting-Room-Command';
const WR_REVOKE_VALUE = 'revoke';

const EXPIRY_HTML = `<!doctype html>
<html><head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0">
  <title>Session expired</title>
</head><body>
  <p>Your session has expired. Reloading to re-enter the queue&hellip;</p>
</body></html>`;

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const cookieName = env.SESSION_COOKIE ?? 'app_session';
    const maxSessionMs = parseInt(env.MAX_SESSION_MS ?? '3600000', 10);
    const cookieHeader = request.headers.get('Cookie');
    const rawCookieValue = getCookieValue(cookieHeader, cookieName);

    // ------------------------------------------------------------------
    // 1. Validate existing session cookie
    // ------------------------------------------------------------------

    const payload = rawCookieValue
      ? await verifyCookie(rawCookieValue, env.HMAC_SECRET)
      : null;

    // ------------------------------------------------------------------
    // 2a. Known session — check wall-clock expiry
    // ------------------------------------------------------------------

    if (payload) {
      const elapsed = Date.now() - payload.acceptedAt;

      if (elapsed > maxSessionMs) {
        // Session has exceeded the maximum lifetime. Revoke and auto-reload.
        return new Response(EXPIRY_HTML, {
          status: 503,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Retry-After': '0',
            'Cache-Control': 'no-store',
            'Set-Cookie': buildClearCookieHeader(cookieName),
            [WR_REVOKE_HEADER]: WR_REVOKE_VALUE,
          },
        });
      }

      // Session is still active. Proxy to origin.
      return proxyToOrigin(request, null, cookieName);
    }

    // ------------------------------------------------------------------
    // 2b. No valid cookie — newly admitted user. Issue a session cookie.
    // ------------------------------------------------------------------

    const sid = newSessionId();
    const cookieValue = await signCookie({ sid, acceptedAt: Date.now() }, env.HMAC_SECRET);
    return proxyToOrigin(request, cookieValue, cookieName);
  },
};

// ---------------------------------------------------------------------------
// Proxy helper
// ---------------------------------------------------------------------------

async function proxyToOrigin(
  request: Request,
  newCookieValue: string | null,
  cookieName: string,
): Promise<Response> {
  // Strip the app_session cookie from the upstream request.
  const upstreamRequest = new Request(request, {
    headers: stripCookie(request.headers, cookieName),
  });

  const originResponse = await fetch(upstreamRequest);
  const responseHeaders = new Headers(originResponse.headers);

  if (newCookieValue) {
    responseHeaders.append('Set-Cookie', buildSetCookieHeader(cookieName, newCookieValue));
  }

  return new Response(originResponse.body, {
    status: originResponse.status,
    statusText: originResponse.statusText,
    headers: responseHeaders,
  });
}

function stripCookie(headers: Headers, cookieName: string): Headers {
  const out = new Headers(headers);
  const cookieHeader = out.get('Cookie');
  if (!cookieHeader) return out;

  const filtered = cookieHeader
    .split(';')
    .map((p) => p.trim())
    .filter((p) => !p.startsWith(cookieName + '='))
    .join('; ');

  if (filtered) {
    out.set('Cookie', filtered);
  } else {
    out.delete('Cookie');
  }

  return out;
}
