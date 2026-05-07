/**
 * cookie.ts
 *
 * HMAC-SHA256 signed session cookie helpers.
 *
 * Cookie format (URL-safe base64, dot-separated):
 *   <base64url(payload JSON)>.<base64url(HMAC-SHA256 signature)>
 *
 * Payload:
 *   { sid: string, acceptedAt: number }
 *
 * The signature covers the payload bytes, so the cookie cannot be forged
 * or modified without knowledge of HMAC_SECRET.
 */

export interface SessionPayload {
  /** Stable session identifier (UUID v4). */
  sid: string;
  /** Unix timestamp (ms) when the user was first admitted by this Worker. */
  acceptedAt: number;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function base64urlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(padded);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

// ---------------------------------------------------------------------------
// Key import
// ---------------------------------------------------------------------------

let _keyCache: Promise<CryptoKey> | undefined;

async function importKey(secret: string): Promise<CryptoKey> {
  if (_keyCache) return _keyCache;
  const enc = new TextEncoder();
  _keyCache = crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
  return _keyCache;
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/**
 * Produce a signed cookie value from a session payload.
 */
export async function signCookie(payload: SessionPayload, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64urlEncode(enc.encode(payloadJson).buffer as ArrayBuffer);

  const key = await importKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
  const sigB64 = base64urlEncode(sig);

  return `${payloadB64}.${sigB64}`;
}

/**
 * Verify and decode a cookie value. Returns null if invalid or tampered.
 */
export async function verifyCookie(
  value: string,
  secret: string,
): Promise<SessionPayload | null> {
  const parts = value.split('.');
  if (parts.length !== 2) return null;

  const [payloadB64, sigB64] = parts;

  const enc = new TextEncoder();
  const key = await importKey(secret);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64urlDecode(sigB64);
  } catch {
    return null;
  }

  const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payloadB64));
  if (!valid) return null;

  try {
    const payloadBytes = base64urlDecode(payloadB64);
    const payloadJson = new TextDecoder().decode(payloadBytes);
    const payload = JSON.parse(payloadJson) as SessionPayload;
    if (typeof payload.sid !== 'string' || typeof payload.acceptedAt !== 'number') return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

/**
 * Parse the Cookie request header and return the value for `name`, or null.
 */
export function getCookieValue(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k.trim() === name) return rest.join('=').trim();
  }
  return null;
}

/**
 * Build a Set-Cookie header value for the session cookie.
 *
 * - HttpOnly: not accessible from JavaScript
 * - Secure: HTTPS only
 * - SameSite=Lax: safe default; change to Strict if the app doesn't need
 *   cross-origin top-level navigation to preserve the cookie
 * - Path=/: covers the entire hostname
 * - No Expires: session cookie (expires when the browser session ends,
 *   the Worker's 1-hour wall-clock check is the real enforcer)
 */
export function buildSetCookieHeader(name: string, value: string): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/**
 * Build a Set-Cookie header that clears the session cookie.
 */
export function buildClearCookieHeader(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

// ---------------------------------------------------------------------------
// UUID helper (crypto.randomUUID available in Workers runtime)
// ---------------------------------------------------------------------------

export function newSessionId(): string {
  return crypto.randomUUID();
}
