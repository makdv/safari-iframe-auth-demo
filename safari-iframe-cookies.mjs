// Run with `node safari-iframe-cookies.mjs` using an already trusted mkcert CA.
// The identity service and partner simulate login using loopback-only servers.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const web = 'https://web.127-0-0-1.sslip.io:8740';
const id = 'https://id.127-0-0-1.sslip.io:8741';
const partner = 'https://avia.127-0-0-1.nip.io:8742';
const origins = [web, id, partner];
const hosts = origins.map((origin) => new URL(origin).hostname);
const storageAccessFlow = 'storage-access';
const flows = new Set(['iframe', 'partitioned', storageAccessFlow]);
const partnerFlows = new Map();
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
  const ca = execFileSync('mkcert', ['-CAROOT'], { encoding: 'utf8' }).trim();
  if (!existsSync(join(ca, 'rootCA.pem'))) {
    throw new Error('This HTTPS demo needs a trusted local CA from mkcert.');
  }

  const directory = mkdtempSync(join(tmpdir(), 'safari-iframe-cookies-'));
  try {
    const cert = join(directory, 'cert.pem');
    const key = join(directory, 'key.pem');
    execFileSync('mkcert', ['-cert-file', cert, '-key-file', key, ...hosts]);
    return { cert: readFileSync(cert), key: readFileSync(key) };
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

function sessionCookie(name, value, partitioned, sameSite = 'None') {
  const partition = partitioned ? '; Partitioned' : '';
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${sessionSeconds}${partition}`;
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

function rememberPartnerFlow(attempt, { flow, sameSite }, phase, lifetime, value) {
  const entry = { flow, sameSite, phase, value, expiresAt: Date.now() + lifetime * 1000 };
  partnerFlows.set(attempt, entry);
  setTimeout(() => {
    if (partnerFlows.get(attempt) === entry) partnerFlows.delete(attempt);
  }, lifetime * 1000).unref();
}

function activePartnerFlow(attempt) {
  const entry = partnerFlows.get(attempt);
  return entry?.expiresAt > Date.now() ? entry : undefined;
}

function cookieMode(flow) {
  return flow === 'partitioned' ? 'Partitioned' : 'Regular';
}

function partnerCookieName(flow, attempt) {
  return `${partnerCookiePrefix}${cookieMode(flow).toLowerCase()}-${attempt}`;
}

function partnerLandingUrl(attempt, flow) {
  const path = flow === storageAccessFlow ? '/storage-access/signed-in' : '/';
  return route(partner, path, attempt, flow);
}

function partnerCallback(response, searchParams, attempt, flow) {
  const state = activePartnerFlow(attempt);
  response.setHeader('Referrer-Policy', 'no-referrer');
  if (state?.phase !== 'callback' || state.flow !== flow || state.value !== searchParams.get('code')) {
    return page(response, 403, '403 · Partner callback expired or invalid', `<p>${signInOptions(state?.sameSite)}</p>`);
  }

  const session = randomBytes(24).toString('base64url');
  rememberPartnerFlow(attempt, state, 'session', sessionSeconds, session);
  const cookie = sessionCookie(partnerCookieName(flow, attempt), session, flow === 'partitioned', state.sameSite);
  console.log(`${flow} ${attempt} partner /callback sent Set-Cookie with SameSite=${state.sameSite}`);
  return redirect(response, partnerLandingUrl(attempt, flow), cookie);
}

function findPartnerSession(request, attempt, flow) {
  // A result URL checks its own run. The bare partner page accepts any active session cookie.
  let receivedCookie = false;
  for (const [name, value] of readCookies(request)) {
    if (!name.startsWith(partnerCookiePrefix) || !value) continue;
    const sessionAttempt = name.slice(name.lastIndexOf('-') + 1);
    if (attempt && sessionAttempt !== attempt) continue;
    if (flow && name !== partnerCookieName(flow, sessionAttempt)) continue;
    receivedCookie = true;
    const state = activePartnerFlow(sessionAttempt);
    if (state?.phase !== 'session' || state.value !== value || partnerCookieName(state.flow, sessionAttempt) !== name) continue;
    return { session: { name, flow: state.flow, sameSite: state.sameSite }, receivedCookie };
  }
  return { receivedCookie };
}

function partnerMainPage(request, response, attempt, flow, selectedSameSite) {
  const { session, receivedCookie } = findPartnerSession(request, attempt, flow);
  const expected = activePartnerFlow(attempt);
  const callback = session ?? (expected?.phase === 'session' && expected.flow === flow ? expected : undefined);
  const status = session ? 200 : 403;
  const title = session ? '200 · Hello from the partner main page' : '403 · Partner session required';
  const failure = receivedCookie ? 'The partner received an invalid or expired session cookie.' : 'The partner session cookie for this run is missing.';
  const result = session ? `${cookieMode(session.flow)} cookie <code>${session.name}</code> works.` : failure;
  const mainUrl = attempt ? route(partner, '/', attempt, flow, flow ? undefined : selectedSameSite) : `${partner}/`;
  const cookieFlags = callback?.flow === 'partitioned' ? '; Partitioned' : '';
  console.log(`${flow ?? 'gate'} ${attempt ?? 'direct'} partner / returned HTTP ${status}`);
  return page(response, status, title, `
    <p>${result}</p>
    <dl>
      <dt>Identity provider /login</dt><dd>${callback ? 'Cookie verified before the partner callback' : 'Sign-in required'}</dd>
      ${callback ? `<dt>Partner /callback cookie</dt><dd><code>SameSite=${callback.sameSite}${cookieFlags}</code></dd>` : ''}
    </dl>
    <p>${link(mainUrl, 'Check partner session again')} · ${signInOptions(callback?.sameSite ?? selectedSameSite)}</p>`, `
      body { margin-block: .8rem; }
      h1 { font-size: 1.25rem; }
      code { overflow-wrap: anywhere; }`);
}

function storageAccessPage(response, attempt, sameSite) {
  const start = route(partner, '/start', attempt, storageAccessFlow, sameSite);
  const check = route(partner, '/storage-access/session', attempt, storageAccessFlow);
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
  const { session } = findPartnerSession(request, attempt, storageAccessFlow);
  if (!session) {
    return page(response, 403, '403 · Partner session required', '<p>Return to the original tab and start a fresh sign-in.</p>');
  }
  if (confirmed) {
    return page(response, 200, 'Return to the bottom sheet', `
      <p>Sign-in confirmed. If this tab stays open, close it and select <strong>Continue in the sheet</strong> in your original tab.</p>
      <script>window.close();</script>`);
  }

  const confirm = new URL(partnerLandingUrl(attempt, storageAccessFlow));
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

function storageAccessSession(request, response, attempt) {
  const { session } = findPartnerSession(request, attempt, storageAccessFlow);
  const state = activePartnerFlow(attempt);
  const sameSite = state?.phase === 'session' && state.flow === storageAccessFlow ? state.sameSite : undefined;
  const status = session ? 200 : 403;
  console.log(`${storageAccessFlow} ${attempt} partner session check returned HTTP ${status}`);
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify({ cookieName: session?.name, sameSite }));
}

function serve(origin, request, response) {
  const url = new URL(request.url, origin);
  const { pathname, searchParams } = url;
  const sameSite = searchParams.get('sameSite') === 'Lax' ? 'Lax' : 'None';
  response.setHeader('Cache-Control', 'no-store');
  if (request.headers.host !== new URL(origin).host || request.method !== 'GET') {
    response.writeHead(400).end();
    return;
  }

  if (origin === web && pathname === '/') {
    return page(response, 200, 'Safari bottom-sheet cookie demo', `
      <p>The web app and identity provider are sibling subdomains. The partner is on a different site.</p>
      <p>Partner <code>/start</code> → ID <code>/authorize</code> → ID <code>/login</code> → Partner <code>/callback</code> → Partner main page</p>
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
          <button type="submit" formaction="${partner}/">Check partner without sign-in (expected 403)</button>
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
  const validAttempt = /^[a-f0-9]{16}$/.test(attempt ?? '');
  if (origin === partner && pathname === '/') {
    return partnerMainPage(request, response, validAttempt ? attempt : undefined,
      validAttempt && flows.has(flow) ? flow : undefined, sameSite);
  }
  if (!validAttempt || !flows.has(flow)) {
    response.writeHead(404).end();
    return;
  }

  if (origin === partner && pathname === '/start') {
    const loginAttempt = flow === storageAccessFlow ? attempt : randomBytes(8).toString('hex');
    const state = activePartnerFlow(loginAttempt);
    if (state && (state.flow !== flow || state.sameSite !== sameSite)) {
      return page(response, 403, '403 · Sign-in attempt invalid', `<p>${signInOptions(sameSite)}</p>`);
    }
    if (state?.phase === 'session') return redirect(response, partnerLandingUrl(loginAttempt, flow));
    if (!state) rememberPartnerFlow(loginAttempt, { flow, sameSite }, 'login', sessionSeconds);
    return redirect(response, route(id, '/authorize', loginAttempt, flow));
  }
  if (origin === partner) {
    if (pathname === '/callback') return partnerCallback(response, searchParams, attempt, flow);
    if (pathname === '/session') return redirect(response, route(partner, '/', attempt, flow));
    if (flow === storageAccessFlow) {
      if (pathname === '/storage-access') return storageAccessPage(response, attempt, sameSite);
      if (pathname === '/storage-access/signed-in') return storageAccessSignedIn(request, response, attempt, searchParams.get('confirmed') === '1');
      if (pathname === '/storage-access/session') return storageAccessSession(request, response, attempt);
    }
  }
  if (origin !== id || !['/authorize', '/login'].includes(pathname)) {
    response.writeHead(404).end();
    return;
  }

  const state = activePartnerFlow(attempt);
  if (state?.flow !== flow) {
    return page(response, 403, '403 · Sign-in attempt expired', `<p>${signInOptions()}</p>`);
  }

  const name = `__Host-demo-${attempt}-${flow}`;
  if (pathname === '/authorize') {
    console.log(`${flow} ${attempt} /authorize sent Set-Cookie`);
    const cookie = sessionCookie(name, 'issued', flow === 'partitioned');
    return redirect(response, route(id, '/login', attempt, flow), cookie);
  }

  if (readCookies(request).get(name) !== 'issued') {
    console.log(`${flow} ${attempt} /login returned HTTP 403 because the identity cookie was missing`);
    return page(response, 403, '403 · Identity provider cookie missing', `
      <p><code>/authorize</code> sent a ${cookieMode(flow).toLowerCase()} cookie with <code>SameSite=None</code>. <code>/login</code> received no matching cookie.</p>
      <p>${signInOptions(state.sameSite)}</p>`);
  }

  if (state.phase === 'session') return redirect(response, partnerLandingUrl(attempt, flow));
  const code = state.phase === 'callback' ? state.value : randomBytes(24).toString('base64url');
  if (state.phase === 'login') rememberPartnerFlow(attempt, state, 'callback', codeSeconds, code);
  const callback = new URL(route(partner, '/callback', attempt, flow));
  callback.searchParams.set('code', code);
  response.setHeader('Referrer-Policy', 'no-referrer');
  console.log(`${flow} ${attempt} /login verified the identity cookie and redirected to the partner callback`);
  return redirect(response, callback.href);
}

await Promise.all(hosts.map(async (host) => {
  const addresses = await lookup(host, { all: true });
  if (!addresses.length || addresses.some(({ address }) => address !== '127.0.0.1')) {
    throw new Error(`${host} must resolve to 127.0.0.1 to run this demo.`);
  }
}));

const tls = localCertificate();
await Promise.all(origins.map((origin) => new Promise((resolve, reject) => {
  const server = createServer(tls, (request, response) => serve(origin, request, response));
  server.once('error', reject);
  server.listen(Number(new URL(origin).port), '127.0.0.1', resolve);
})));
console.log(`Open ${web} in Safari or Chrome.`);
