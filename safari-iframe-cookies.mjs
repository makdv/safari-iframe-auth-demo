// Run with `node safari-iframe-cookies.mjs` using an already trusted mkcert CA.
// The identity service and partner simulate login using loopback-only servers.
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const web = 'https://web.127-0-0-1.sslip.io:8740';
const id = 'https://id.127-0-0-1.sslip.io:8741';
const partner = 'https://avia.127-0-0-1.nip.io:8742';
const origins = [web, id, partner];
const hosts = origins.map((origin) => new URL(origin).hostname);
const storageAccessFlow = 'storage-access';
const flows = new Set(['iframe', 'partitioned', storageAccessFlow]);
const protectedPath = '/protected';
const clientId = 'avia-demo';
const redirectUri = `${partner}/callback`;
const attemptPattern = /^[a-f0-9]{16}$/;
const opaqueValuePattern = /^[A-Za-z0-9_-]{43}$/;
const verifierPattern = /^[A-Za-z0-9._~-]{43,128}$/;
const partnerTransactions = new Map();
const partnerSessions = new Map();
const identityTransactions = new Map();
const authorizationCodes = new Map();
const partnerCookiePrefix = '__Host-demo-partner-';
const sessionSeconds = 600;
const codeSeconds = 60;

const bottomSheetStyles = `
    .bottom-sheet {
      position: fixed;
      inset: auto 0 0;
      display: flex;
      flex-direction: column;
      width: min(calc(100% - 2rem), 52rem);
      height: 58dvh;
      margin-inline: auto;
      box-sizing: border-box;
      overflow: hidden;
      background: Canvas;
      border: 1px solid color-mix(in srgb, CanvasText 20%, Canvas);
      border-bottom: 0;
      border-radius: 1rem 1rem 0 0;
      box-shadow: 0 -6px 32px rgb(0 0 0 / 12%);
      transition: height 180ms ease-out;
    }
    .bottom-sheet[data-dragging] { transition: none; }
    .sheet-header {
      flex: none;
      border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, Canvas);
    }
    .sheet-handle {
      display: grid;
      place-items: center;
      width: 100%;
      height: 44px;
      cursor: grab;
      touch-action: none;
      user-select: none;
    }
    .sheet-handle:active { cursor: grabbing; }
    .sheet-handle:focus-visible { outline: 2px solid Highlight; outline-offset: -3px; }
    .sheet-handle span { width: 2.75rem; height: .3rem; border-radius: 1rem; background: GrayText; }
    .sheet-title { margin: 0; padding: 0 1.25rem .7rem; font-size: 1rem; }
    .bottom-sheet iframe { flex: 1; width: 100%; height: auto; min-height: 0; border: 0; border-radius: 0; }
    .bottom-sheet[data-collapsed]:not([data-dragging]) iframe { visibility: hidden; }
    @media (max-width: 40rem) { .bottom-sheet { width: 100%; } }
    @media (prefers-reduced-motion: reduce) { .bottom-sheet { transition: none; } }`;

const bottomSheet = `
  <aside class="bottom-sheet" aria-labelledby="sheet-title">
    <header class="sheet-header">
      <div class="sheet-handle" role="slider" tabindex="0" aria-label="Bottom sheet height"
        aria-orientation="vertical" aria-valuemin="0" aria-valuemax="2" aria-valuenow="1" aria-valuetext="Half height">
        <span aria-hidden="true"></span>
      </div>
      <h2 class="sheet-title" id="sheet-title">Partner login</h2>
    </header>
    <iframe src="/frame" title="Bottom-sheet login options"></iframe>
  </aside>
  <script>
    const sheet = document.querySelector('.bottom-sheet');
    const header = document.querySelector('.sheet-header');
    const handle = document.querySelector('.sheet-handle');
    const labels = ['Collapsed', 'Half height', 'Expanded'];
    let position = 1;
    let drag;

    const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

    function snapHeights() {
      const collapsed = header.offsetHeight + 1;
      const expanded = Math.max(collapsed, window.innerHeight - 16);
      return [collapsed, clamp(Math.round(window.innerHeight * .58), collapsed, expanded), expanded];
    }

    function snapTo(next) {
      position = clamp(next, 0, labels.length - 1);
      sheet.style.height = snapHeights()[position] + 'px';
      sheet.toggleAttribute('data-collapsed', position === 0);
      handle.setAttribute('aria-valuenow', position);
      handle.setAttribute('aria-valuetext', labels[position]);
    }

    handle.addEventListener('pointerdown', (event) => {
      if (!event.isPrimary || event.button !== 0) return;
      event.preventDefault();
      handle.focus({ preventScroll: true });
      handle.setPointerCapture(event.pointerId);
      drag = { id: event.pointerId, y: event.clientY, height: sheet.getBoundingClientRect().height };
      sheet.setAttribute('data-dragging', '');
    });

    handle.addEventListener('pointermove', (event) => {
      if (drag?.id !== event.pointerId) return;
      const [min, , max] = snapHeights();
      sheet.style.height = clamp(drag.height + drag.y - event.clientY, min, max) + 'px';
    });

    function finishDrag(event) {
      if (drag?.id !== event.pointerId) return;
      const distance = drag.y - event.clientY;
      const height = drag.height + distance;
      drag = undefined;
      sheet.removeAttribute('data-dragging');

      if (event.type !== 'pointerup') return snapTo(position);
      if (Math.abs(distance) < 5) return snapTo((position + 1) % labels.length);

      const heights = snapHeights();
      const nearest = heights.reduce((best, snapHeight, index) =>
        Math.abs(snapHeight - height) < Math.abs(heights[best] - height) ? index : best, position);
      const next = nearest === position && Math.abs(distance) >= 24 ? position + Math.sign(distance) : nearest;
      snapTo(next);
    }

    handle.addEventListener('pointerup', finishDrag);
    handle.addEventListener('pointercancel', finishDrag);
    handle.addEventListener('lostpointercapture', finishDrag);
    handle.addEventListener('keydown', (event) => {
      const targets = {
        ArrowUp: position + 1, ArrowRight: position + 1,
        ArrowDown: position - 1, ArrowLeft: position - 1,
        Home: 0, End: 2, Enter: (position + 1) % labels.length, ' ': (position + 1) % labels.length,
      };
      if (!Object.hasOwn(targets, event.key)) return;
      event.preventDefault();
      snapTo(targets[event.key]);
    });
    window.addEventListener('resize', () => {
      if (!drag) snapTo(position);
    });
    snapTo(position);
  </script>`;

function localCertificate() {
  const caRoot = execFileSync('mkcert', ['-CAROOT'], { encoding: 'utf8' }).trim();
  const caPath = join(caRoot, 'rootCA.pem');
  if (!existsSync(caPath)) {
    throw new Error('This HTTPS demo needs a trusted local CA from mkcert.');
  }

  const directory = mkdtempSync(join(tmpdir(), 'safari-iframe-cookies-'));
  try {
    const cert = join(directory, 'cert.pem');
    const key = join(directory, 'key.pem');
    execFileSync('mkcert', ['-cert-file', cert, '-key-file', key, ...hosts]);
    return { cert: readFileSync(cert), key: readFileSync(key), ca: readFileSync(caPath) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function route(origin, path, attempt, flow, sameSite) {
  const query = new URLSearchParams({ attempt });
  if (flow) query.set('flow', flow);
  if (sameSite) query.set('sameSite', sameSite);
  return `${origin}${path}?${query}`;
}

function link(url, label) {
  return `<a href="${url.replaceAll('&', '&amp;')}" target="_self">${label}</a>`;
}

function signInOptions(sameSite) {
  const query = sameSite === 'Lax' ? '?sameSite=Lax' : '';
  return link(`${web}/frame${query}`, 'Back to sign-in choices');
}

function page(response, status, title, body, styles = '') {
  response.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  response.end(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<link rel="icon" href="data:,">
<style>
  :root { color-scheme: light dark; font: 17px/1.55 system-ui, sans-serif; }
  body { max-width: 56rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.55rem; line-height: 1.2; }
  li + li { margin-top: .5rem; }
  iframe { width: 100%; height: 26rem; border: 1px solid GrayText; border-radius: .4rem; }
  dt { font-weight: 600; }
  dd { margin: 0 0 .6rem; }
  ${styles}
</style>
<main>
  <h1>${title}</h1>
  ${body}
</main>
</html>`);
}

function redirect(response, location, cookie) {
  response.setHeader('Location', location);
  if (cookie) response.setHeader('Set-Cookie', cookie);
  response.writeHead(302).end();
}

function demoCookie(name, value, { partitioned, sameSite = 'None', maxAge = sessionSeconds }) {
  const partition = partitioned ? '; Partitioned' : '';
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${partition}`;
}

function readCookies(request) {
  const cookies = new Map();
  for (const field of (request.headers.cookie ?? '').split(';')) {
    const pair = field.trim();
    const equals = pair.indexOf('=');
    if (equals < 1) continue;
    const name = pair.slice(0, equals);
    if (!cookies.has(name)) cookies.set(name, pair.slice(equals + 1));
  }
  return cookies;
}

function remember(store, key, value, lifetime = sessionSeconds) {
  const entry = { ...value, expiresAt: Date.now() + lifetime * 1000 };
  store.set(key, entry);
  setTimeout(() => {
    if (store.get(key) === entry) store.delete(key);
  }, lifetime * 1000).unref();
}

function activeEntry(store, key) {
  const entry = store.get(key);
  return entry?.expiresAt > Date.now() ? entry : undefined;
}

function cookieMode(flow) {
  return flow === 'partitioned' ? 'Partitioned' : 'Regular';
}

function partnerCookieName(flow, attempt) {
  return `${partnerCookiePrefix}${cookieMode(flow).toLowerCase()}-${attempt}`;
}

function pkceChallenge(verifier) {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

function transactionCookieName(attempt) {
  return `__Host-demo-transaction-${attempt}`;
}

function startPartnerSignIn(response, flow, sameSite, embedAttempt) {
  const attempt = randomBytes(8).toString('hex');
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const browserKey = randomBytes(32).toString('base64url');
  remember(partnerTransactions, state, { attempt, flow, sameSite, embedAttempt, verifier, browserKey });

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: 'S256',
    flow,
    sameSite,
  });
  const cookie = demoCookie(transactionCookieName(attempt), browserKey, { partitioned: flow === 'partitioned' });
  return redirect(response, `${id}/authorize?${params}`, cookie);
}

async function readBody(message) {
  message.setEncoding('utf8');
  let body = '';
  for await (const chunk of message.iterator({ destroyOnReturn: false })) {
    body += chunk;
    if (body.length > 4096) {
      message.resume();
      return undefined;
    }
  }
  return body;
}

async function exchangeCode(code, verifier) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    redirect_uri: redirectUri,
    code,
    code_verifier: verifier,
  }).toString();

  const response = await new Promise((resolve, reject) => {
    const request = httpsRequest(`${id}/token`, {
      ca: identityCA,
      method: 'POST',
      timeout: 5000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, resolve);
    request.on('error', reject);
    request.on('timeout', () => request.destroy(new Error('Token request timed out')));
    request.end(body);
  });

  const payload = JSON.parse(await readBody(response));
  if (response.statusCode === 400 && payload?.error === 'invalid_grant') return false;
  if (response.statusCode !== 200 || payload?.token_type !== 'Bearer' ||
      typeof payload.access_token !== 'string' || !opaqueValuePattern.test(payload.access_token)) {
    throw new Error('Unexpected token response');
  }
  return true;
}

async function partnerCallback(request, response, searchParams) {
  response.setHeader('Referrer-Policy', 'no-referrer');
  const [state, extraState] = searchParams.getAll('state');
  const [code, extraCode] = searchParams.getAll('code');
  const transaction = activeEntry(partnerTransactions, state);
  if (!transaction || extraState !== undefined || extraCode !== undefined || !opaqueValuePattern.test(code ?? '')) {
    return page(response, 403, '403 · Invalid or expired sign-in response', `<p>${signInOptions(transaction?.sameSite)}</p>`);
  }

  const { attempt, flow, sameSite, embedAttempt, verifier, browserKey } = transaction;
  const transactionCookie = transactionCookieName(attempt);
  if (readCookies(request).get(transactionCookie) !== browserKey) {
    return page(response, 403, '403 · Avia sign-in cookie missing or invalid', `
      <p>The callback needs the transaction cookie from Avia’s <code>/start</code> to verify <code>state</code>.</p>
      <p>${signInOptions(sameSite)}</p>`);
  }

  // Claim this transaction before awaiting the exchange so a second callback cannot use it.
  partnerTransactions.delete(state);
  let exchanged;
  try {
    exchanged = await exchangeCode(code, verifier);
  } catch {
    console.log(`${flow} ${attempt} partner /callback could not complete the ID /token request`);
    return page(response, 502, '502 · Partner token exchange unavailable', `<p>${signInOptions(sameSite)}</p>`);
  }
  if (!exchanged) {
    return page(response, 403, '403 · ID provider rejected the code exchange', `<p>${signInOptions(sameSite)}</p>`);
  }

  const session = randomBytes(24).toString('base64url');
  remember(partnerSessions, attempt, { flow, sameSite, embedAttempt, value: session });
  const partitioned = flow === 'partitioned';
  const cookie = demoCookie(partnerCookieName(flow, attempt), session, { partitioned, sameSite });
  const clearTransaction = demoCookie(transactionCookie, '', { partitioned, maxAge: 0 });
  console.log(`${flow} ${attempt} partner /callback verified state and exchanged the code with PKCE, then set SameSite=${sameSite}`);
  return redirect(response, route(partner, protectedPath, attempt, flow), [cookie, clearTransaction]);
}

function authorize(response, searchParams, sameSite) {
  const flow = searchParams.get('flow');
  const state = searchParams.get('state');
  const challenge = searchParams.get('code_challenge');
  if (!flows.has(flow) || searchParams.get('client_id') !== clientId ||
      searchParams.get('redirect_uri') !== redirectUri || searchParams.get('response_type') !== 'code' ||
      searchParams.get('scope') !== 'openid' || searchParams.get('code_challenge_method') !== 'S256' ||
      !opaqueValuePattern.test(challenge) || !opaqueValuePattern.test(state)) {
    return page(response, 400, '400 · Invalid authorization request', `<p>${signInOptions(sameSite)}</p>`);
  }

  const attempt = randomBytes(8).toString('hex');
  const loginKey = randomBytes(32).toString('base64url');
  remember(identityTransactions, attempt, { flow, state, challenge, loginKey, sameSite });
  const cookie = demoCookie(`__Host-demo-id-${attempt}`, loginKey, { partitioned: flow === 'partitioned' });
  console.log(`${flow} ${attempt} ID /authorize sent Set-Cookie`);
  return redirect(response, route(id, '/login', attempt), cookie);
}

function identityLogin(request, response, attempt) {
  const transaction = activeEntry(identityTransactions, attempt);
  if (!transaction) {
    return page(response, 403, '403 · Sign-in attempt expired', `<p>${signInOptions()}</p>`);
  }

  const { flow, state, challenge, loginKey, sameSite } = transaction;
  const name = `__Host-demo-id-${attempt}`;
  if (readCookies(request).get(name) !== loginKey) {
    console.log(`${flow} ${attempt} ID /login returned HTTP 403 because the identity cookie was missing or invalid`);
    return page(response, 403, '403 · Identity provider cookie missing or invalid', `
      <p><code>/authorize</code> sent a ${cookieMode(flow).toLowerCase()} cookie with <code>SameSite=None</code>. <code>/login</code> received no matching cookie.</p>
      <p>${signInOptions(sameSite)}</p>`);
  }

  identityTransactions.delete(attempt);
  const code = randomBytes(32).toString('base64url');
  remember(authorizationCodes, code, { challenge, clientId, redirectUri }, codeSeconds);
  const params = new URLSearchParams({ code, state });
  const clearTransaction = demoCookie(name, '', { partitioned: flow === 'partitioned', maxAge: 0 });
  console.log(`${flow} ${attempt} ID /login verified the identity cookie and issued a one-time code`);
  return redirect(response, `${redirectUri}?${params}`, clearTransaction);
}

function tokenResponse(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', Pragma: 'no-cache' });
  response.end(JSON.stringify(payload));
}

async function issueToken(request, response) {
  const contentType = request.headers['content-type']?.split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/x-www-form-urlencoded') {
    return tokenResponse(response, 400, { error: 'invalid_request' });
  }
  const body = await readBody(request);
  if (!body) return tokenResponse(response, 400, { error: 'invalid_request' });
  const params = new URLSearchParams(body);
  if (params.get('grant_type') !== 'authorization_code') {
    return tokenResponse(response, 400, { error: 'unsupported_grant_type' });
  }

  const code = params.get('code');
  const verifier = params.get('code_verifier');
  const grant = activeEntry(authorizationCodes, code);
  if (!grant || grant.clientId !== params.get('client_id') || grant.redirectUri !== params.get('redirect_uri') ||
      !verifierPattern.test(verifier) || grant.challenge !== pkceChallenge(verifier)) {
    return tokenResponse(response, 400, { error: 'invalid_grant' });
  }

  authorizationCodes.delete(code);
  console.log('ID /token verified S256 PKCE and redeemed the one-time code');
  return tokenResponse(response, 200, { access_token: randomBytes(32).toString('base64url'), token_type: 'Bearer' });
}

function findPartnerSession(request, { attempt, flow, embedAttempt, sameSite }) {
  // A result URL checks its own run. The bare partner page accepts any active session cookie.
  let receivedCookie = false;
  for (const [name, value] of readCookies(request)) {
    if (!name.startsWith(partnerCookiePrefix) || !value) continue;
    const sessionAttempt = name.slice(name.lastIndexOf('-') + 1);
    if (attempt && sessionAttempt !== attempt) continue;
    if (flow && name !== partnerCookieName(flow, sessionAttempt)) continue;
    const state = activeEntry(partnerSessions, sessionAttempt);
    if (embedAttempt && (state?.embedAttempt !== embedAttempt || state.sameSite !== sameSite)) continue;
    receivedCookie = true;
    if (!state || state.value !== value || partnerCookieName(state.flow, sessionAttempt) !== name) continue;
    return { session: { name, flow: state.flow, sameSite: state.sameSite }, receivedCookie };
  }
  return { receivedCookie };
}

function partnerMainPage(request, response, attempt, flow, selectedSameSite) {
  const { session, receivedCookie } = findPartnerSession(request, { attempt, flow });
  const expected = activeEntry(partnerSessions, attempt);
  const callback = session ?? (expected?.flow === flow ? expected : undefined);
  const status = session ? 200 : 403;
  const title = session ? '200 · Hello from the partner main page' : '403 · Partner session required';
  const failure = receivedCookie ? 'The partner received an invalid or expired session cookie.' : 'The partner session cookie for this run is missing.';
  const result = session ? `${cookieMode(session.flow)} cookie <code>${session.name}</code> works.` : failure;
  const mainUrl = attempt ? route(partner, protectedPath, attempt, flow, flow ? undefined : selectedSameSite) : `${partner}${protectedPath}`;
  const cookieFlags = callback?.flow === 'partitioned' ? '; Partitioned' : '';
  console.log(`${flow ?? 'gate'} ${attempt ?? 'direct'} partner ${protectedPath} returned HTTP ${status}`);
  return page(response, status, title, `
    <p>${result}</p>
    <dl>
      <dt>Identity provider /login</dt><dd>${callback ? 'Cookie verified before the partner callback' : 'Sign-in required'}</dd>
      ${callback ? `<dt>Partner /callback</dt><dd>State verified. Code exchanged at ID /token with PKCE.</dd>
      <dt>Partner session cookie</dt><dd><code>SameSite=${callback.sameSite}${cookieFlags}</code></dd>` : ''}
    </dl>
    <p>${link(mainUrl, 'Check partner session again')} · ${signInOptions(callback?.sameSite ?? selectedSameSite)}</p>`, `
      body { margin-block: .8rem; }
      h1 { font-size: 1.25rem; }
      code { overflow-wrap: anywhere; }`);
}

function storageAccessPage(response, attempt, sameSite) {
  const start = route(partner, '/start', attempt, storageAccessFlow, sameSite);
  const check = `${partner}${protectedPath}?${new URLSearchParams({ embedAttempt: attempt, sameSite })}`;
  return page(response, 200, 'Sign in with Storage Access', `
    <p>Partner session cookie <code>SameSite=${sameSite}</code></p>
    <ol>
      <li><a id="open-partner-sign-in" href="${start.replaceAll('&', '&amp;')}" target="_blank" rel="noopener">Sign in to the partner in a new tab</a> and confirm sign-in on the partner page.</li>
      <li>Return to this sheet and continue.</li>
    </ol>
    <p class="storage-actions">
      <button type="button" id="continue-in-sheet">Continue in the sheet</button>
      ${signInOptions(sameSite)}
    </p>
    <p role="status" id="storage-result"></p>
    <script>
      var signInLink = document.getElementById('open-partner-sign-in');
      var button = document.getElementById('continue-in-sheet');
      var result = document.getElementById('storage-result');
      var checkUrl = ${JSON.stringify(check)};

      signInLink.addEventListener('click', function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        window.open(signInLink.href, '_blank', 'noopener');
      });

      if (typeof document.requestStorageAccess !== 'function') {
        button.disabled = true;
        result.textContent = 'Storage Access is unavailable in this browser. Open the partner tab to continue there.';
      }

      function checkPartnerSession() {
        return fetch(checkUrl, { credentials: 'same-origin' }).then(function (response) {
          if (!response.ok && response.status !== 403) throw new Error('Partner session check failed');
          return response.json().then(function (session) {
            if (response.status === 403) {
              result.textContent = session.sameSite
                ? '403 · Partner session check. Storage access granted. No matching SameSite=' + session.sameSite + ' partner cookie reached the server.'
                : '403 · Partner session check. Finish sign-in in the partner tab or start a fresh attempt.';
              return;
            }
            result.textContent = '200 · Hello from the partner main page. Regular cookie ';
            var name = document.createElement('code');
            name.textContent = session.cookieName;
            result.appendChild(name);
            result.appendChild(document.createTextNode(' works with SameSite=' + session.sameSite + '.'));
          });
        }).catch(function () {
          result.textContent = 'The partner session check failed. Try again or reopen the partner tab.';
        });
      }

      button.addEventListener('click', function () {
        button.disabled = true;
        result.textContent = 'Requesting access to the partner session…';
        document.requestStorageAccess().then(checkPartnerSession, function () {
          result.textContent = 'Storage access was unavailable or declined. Reopen the partner tab to continue there.';
        }).then(function () { button.disabled = false; });
      });
    </script>`, `
      body { margin-block: .8rem; }
      h1 { font-size: 1.25rem; }
      ol { padding-inline-start: 1.4rem; }
      .storage-actions { display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem; }
      button { font: inherit; cursor: pointer; }
      code { overflow-wrap: anywhere; }`);
}

function storageAccessSignedIn(request, response, attempt, confirmed) {
  const { session } = findPartnerSession(request, { attempt, flow: storageAccessFlow });
  if (!session) {
    return page(response, 403, '403 · Partner session required', '<p>Return to the original tab and start a fresh sign-in.</p>');
  }
  if (confirmed) {
    return page(response, 200, 'Return to the bottom sheet', `
      <p>Sign-in confirmed. If this tab stays open, close it and select <strong>Continue in the sheet</strong> in your original tab.</p>
      <script>window.close();</script>`);
  }

  const confirm = new URL(route(partner, protectedPath, attempt, storageAccessFlow));
  confirm.searchParams.set('confirmed', '1');
  return page(response, 200, '200 · Signed in to the partner', `
    <p>The partner received its <code>SameSite=${session.sameSite}</code> session cookie in this tab.</p>
    <p><a id="confirm-sign-in" href="${confirm.href.replaceAll('&', '&amp;')}">Confirm sign-in</a></p>
    <script>
      var confirmLink = document.getElementById('confirm-sign-in');
      confirmLink.addEventListener('click', function (event) {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        window.location.replace(confirmLink.href);
      });
    </script>`);
}

function storageAccessSession(request, response, embedAttempt, sameSite) {
  const { session } = findPartnerSession(request, { embedAttempt, sameSite, flow: storageAccessFlow });
  const now = Date.now();
  const callbackCompleted = session || [...partnerSessions.values()].some((state) =>
    state.embedAttempt === embedAttempt && state.sameSite === sameSite && state.expiresAt > now);
  const status = session ? 200 : 403;
  console.log(`${storageAccessFlow} ${embedAttempt} partner ${protectedPath} returned HTTP ${status}`);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify({ cookieName: session?.name, sameSite: callbackCompleted ? sameSite : undefined }));
}

async function serve(origin, request, response) {
  const url = new URL(request.url, origin);
  const { pathname, searchParams } = url;
  const sameSite = searchParams.get('sameSite') === 'Lax' ? 'Lax' : 'None';
  response.setHeader('Cache-Control', 'no-store');
  if (request.headers.host !== new URL(origin).host) return response.writeHead(400).end();
  if (origin === id && pathname === '/token') {
    if (request.method !== 'POST') return response.writeHead(405, { Allow: 'POST' }).end();
    return issueToken(request, response);
  }
  if (request.method !== 'GET') return response.writeHead(405, { Allow: 'GET' }).end();

  if (origin === id) {
    response.setHeader('Referrer-Policy', 'no-referrer');
    if (pathname === '/authorize') return authorize(response, searchParams, sameSite);
    if (pathname === '/login') return identityLogin(request, response, searchParams.get('attempt'));
    return response.writeHead(404).end();
  }

  if (origin === web && pathname === '/') {
    return page(response, 200, 'Safari bottom-sheet cookie demo', `
      <p>The web app and identity provider are sibling subdomains. The partner is on a different site.</p>
      <p>Public partner <code>/start</code> → ID <code>/authorize</code> → ID <code>/login</code> → Partner <code>/callback</code> → Partner <code>${protectedPath}</code></p>
      ${bottomSheet}`, bottomSheetStyles);
  }

  if (origin === web && pathname === '/frame') {
    const attempt = randomBytes(8).toString('hex');
    return page(response, 200, 'Partner sign-in', `
      <form method="get" action="${partner}/start" target="_self">
        <input type="hidden" name="attempt" value="${attempt}">
        <fieldset>
          <legend>Partner cookie SameSite</legend>
          <label><input type="radio" name="sameSite" value="None"${sameSite === 'None' ? ' checked' : ''}> None</label>
          <label><input type="radio" name="sameSite" value="Lax"${sameSite === 'Lax' ? ' checked' : ''}> Lax</label>
        </fieldset>
        <div class="sign-in-actions">
          <button type="submit" name="flow" value="iframe">Sign in with regular cookies</button>
          <button type="submit" name="flow" value="partitioned">Sign in with partitioned cookies</button>
          <button type="submit" name="flow" value="${storageAccessFlow}" formaction="${partner}/storage-access">Use Storage Access for older Safari</button>
          <button type="submit" formaction="${partner}${protectedPath}">Check partner without sign-in (expected 403)</button>
        </div>
      </form>`, `
        body { margin-block: .8rem; }
        h1 { font-size: 1.15rem; margin: 0; }
        fieldset { border: 0; padding: 0; margin: .4rem 0 .65rem; }
        legend { font-weight: 600; padding: 0; }
        label { margin-inline-end: .8rem; }
        input { margin-inline-start: 0; }
        .sign-in-actions { display: flex; flex-wrap: wrap; gap: .45rem; }
        button { font: inherit; cursor: pointer; }`);
  }

  const attempt = searchParams.get('attempt');
  const flow = searchParams.get('flow');
  const validAttempt = attemptPattern.test(attempt ?? '');
  if (origin === partner && pathname === '/start') {
    const loginFlow = flow ?? 'iframe';
    if (!flows.has(loginFlow)) {
      return page(response, 400, '400 · Unknown sign-in flow', `<p>${signInOptions(sameSite)}</p>`);
    }
    const embedAttempt = loginFlow === storageAccessFlow && validAttempt ? attempt : undefined;
    return startPartnerSignIn(response, loginFlow, sameSite, embedAttempt);
  }
  if (origin === partner && pathname === '/callback') return partnerCallback(request, response, searchParams);
  if (origin === partner && (pathname === protectedPath || pathname === '/')) {
    const embedAttempt = searchParams.get('embedAttempt');
    if (embedAttempt !== null) {
      if (!attemptPattern.test(embedAttempt)) return response.writeHead(400).end();
      return storageAccessSession(request, response, embedAttempt, sameSite);
    }
    if (validAttempt && flow === storageAccessFlow) {
      return storageAccessSignedIn(request, response, attempt, searchParams.get('confirmed') === '1');
    }
    return partnerMainPage(request, response, validAttempt ? attempt : undefined,
      validAttempt && flows.has(flow) ? flow : undefined, sameSite);
  }
  if (!validAttempt || !flows.has(flow)) {
    response.writeHead(404).end();
    return;
  }

  if (origin === partner) {
    if (pathname === '/session') return redirect(response, route(partner, protectedPath, attempt, flow));
    if (flow === storageAccessFlow) {
      if (pathname === '/storage-access') return storageAccessPage(response, attempt, sameSite);
      if (pathname === '/storage-access/signed-in') return storageAccessSignedIn(request, response, attempt, searchParams.get('confirmed') === '1');
      if (pathname === '/storage-access/session') return storageAccessSession(request, response, attempt, sameSite);
    }
  }
  response.writeHead(404).end();
}

await Promise.all(hosts.map(async (host) => {
  const addresses = await lookup(host, { all: true });
  if (!addresses.length || addresses.some(({ address }) => address !== '127.0.0.1')) {
    throw new Error(`${host} must resolve to 127.0.0.1 to run this demo.`);
  }
}));

const { ca: identityCA, ...tls } = localCertificate();
await Promise.all(origins.map((origin) => new Promise((resolve, reject) => {
  const server = createServer(tls, (request, response) => {
    serve(origin, request, response).catch(() => {
      console.error('Demo request failed');
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  });
  server.once('error', reject);
  server.listen(Number(new URL(origin).port), '127.0.0.1', resolve);
})));
console.log(`Open ${web} in Safari or Chrome.`);
