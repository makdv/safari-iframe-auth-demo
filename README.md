# Safari iframe authentication demo

The demo runs a web app, an identity provider, and a partner on three local HTTPS ports. The web app and identity provider share a site. The partner is cross-site and stays inside the draggable bottom sheet.

**Public partner `/start` → ID `/authorize` → ID `/login` → partner `/callback` → protected partner `/protected`.**

1. Avia’s `/start` creates a fresh `state`, a private PKCE verifier, and a short-lived transaction cookie. It sends the S256 challenge to the ID provider.
2. ID `/authorize` sets its own transaction cookie. ID `/login` checks that cookie and redirects to Avia with a one-time code and the original `state`.
3. Avia’s `/callback` matches `state` to the browser’s transaction cookie, then sends the code and the private verifier to ID `POST /token` over HTTPS. The ID provider checks the S256 challenge and consumes the code. This request appears in the server log.
4. Avia issues its session cookie after a successful exchange. `/protected` checks the cookie on the next request.

The SameSite switch controls Avia’s session cookie. Both transaction cookies use `SameSite=None` so the demo can show cases where the exchange succeeds and `/protected` still returns `403`. Use **Check partner without sign-in** to test the gate directly. [PKCE verification](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.6) · [SameSite cookie rules](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.2.7)

## Run locally

With Node.js and an already trusted [mkcert](https://github.com/FiloSottile/mkcert) CA, run the server from this repo.

```sh
node safari-iframe-cookies.mjs
```

Open the [demo](https://web.127-0-0-1.sslip.io:8740/) in a regular Safari window. Choose **None** and **Use Storage Access for older Safari**. Open the sign-in tab, select **Confirm sign-in**, then select **Continue in the sheet** in the original tab. Safari may ask for storage access. **Lax** demonstrates a successful top-level sign-in followed by `403` from the embedded session check.

The demo simulates user authentication, issues an opaque mock token, and stores sessions in memory. In production, Avia’s OIDC client validates the provider’s ID token before creating a session.

## Your side at `web.example.com`

Put this link in `/someinternalurl`, which your bottom sheet already loads in an iframe. `_self` navigates that iframe to Avia’s entry page. The top-level web app and the sheet stay open.

```html
<a href="https://my.avia.com/embed/continue" target="_self">
  Continue in Avia
</a>
```

If your app restricts `frame-src` in its Content Security Policy, include `https://my.avia.com` alongside its existing allowed origins. Avia’s `/embed/continue` must allow `https://web.example.com` in its `frame-ancestors` directive. This demo uses a direct iframe. A sandboxed integration needs scripts, the embedded origin, popups that can escape the iframe sandbox, and storage access on user activation. [WebKit’s sandbox requirements](https://webkit.org/blog/8124/introducing-storage-access-api/#sandboxed-iframes) · [HTML iframe sandbox rules](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)

## Avia’s entry page at `/embed/continue`

Serve this page from `my.avia.com` before the iframe has cookie access. The public `/start` route redirects to Avia’s identity provider. This Storage Access flow opens it in a separate tab.

```html
<a id="sign-in" href="/start" target="_blank" rel="noopener">
  Sign in to Avia in a new tab
</a>
<button id="continue" type="button">Continue in the sheet</button>
<p id="status" role="status"></p>
<script src="/assets/embed-auth.js" defer></script>
```

```js
// /assets/embed-auth.js
const signIn = document.getElementById('sign-in');
const continueButton = document.getElementById('continue');
const statusElement = document.getElementById('status');

signIn.addEventListener('click', (event) => {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  window.open(signIn.href, '_blank', 'noopener');
});

continueButton.addEventListener('click', async () => {
  if (typeof document.requestStorageAccess !== 'function') {
    statusElement.textContent = 'Open the Avia tab to continue there.';
    return;
  }

  try {
    await document.requestStorageAccess();
  } catch {
    statusElement.textContent = 'Storage access was unavailable or declined. Reopen the Avia tab to continue there.';
    return;
  }

  try {
    const response = await fetch('/protected', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (response.ok) {
      statusElement.textContent = 'Signed in to Avia.';
      // Render your signed-in UI here in this iframe document.
    } else if (response.status === 403) {
      statusElement.textContent = 'Avia could not verify the session cookie. Sign in again.';
    } else {
      statusElement.textContent = 'The session check failed. Try again.';
    }
  } catch {
    statusElement.textContent = 'The session check failed. Try again.';
  }
});
```

Call `requestStorageAccess()` from the **Continue in the sheet** click inside Avia’s iframe. After it resolves, check the session from that same iframe document. [WebKit’s Storage Access guide](https://webkit.org/blog/11545/updates-to-the-storage-access-api/) · [Storage Access fetch and cookie rules](https://privacycg.github.io/storage-access/#fetching)

## Avia’s callback and session check

Route the public `/start` through Avia’s existing OAuth or OIDC flow. Keep `/protected` as a fixed, server-controlled continuation. Call `finishEmbeddedSignIn` after the callback has validated the authorization response and created the session. The snippets use Express-style handlers with Avia’s existing cookie parser and `lookupActiveAviaSession` adapter. [OAuth security best practices](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1)

```js
function finishEmbeddedSignIn(res, sessionId) {
  res.set('Cache-Control', 'no-store');
  res.cookie('__Host-avia_session', sessionId, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  });
  return res.redirect(303, '/protected');
}

async function requireAviaSession(req, res, next) {
  res.set('Cache-Control', 'no-store');
  try {
    const sessionId = req.cookies['__Host-avia_session'];
    const session = sessionId && await lookupActiveAviaSession(sessionId);
    if (!session) return res.status(403).json({ signedIn: false });
    res.locals.aviaSession = session;
    next();
  } catch (error) {
    next(error);
  }
}

app.get('/protected', requireAviaSession, (req, res) => {
  if (req.get('Accept') === 'application/json') {
    return res.json({ signedIn: true });
  }
  return res.render('embed-signed-in');
});

app.get('/embed/confirmed', requireAviaSession, (req, res) => {
  res.render('embed-confirmed');
});
```

Use a regular cookie with `SameSite=None; Secure` for Storage Access. The grant still respects `SameSite`, so a `Lax` cookie may work in the sign-in tab and yield `403` inside the cross-site frame. [Storage Access cookie rules](https://privacycg.github.io/storage-access/#cookies)

## Close the sign-in tab after confirmation

For the Storage Access flow, render this link on Avia’s top-level `/protected` page. The click happens on Avia’s site and gives Safari the first-party interaction it needs. [WebKit’s first-party interaction requirements](https://webkit.org/blog/11545/updates-to-the-storage-access-api/#how-to-1-meet-and-greet-the-user-as-first-party)

```html
<a id="confirm" href="/embed/confirmed">Confirm sign-in</a>
<script src="/assets/confirm-embed-sign-in.js" defer></script>
```

```js
// /assets/confirm-embed-sign-in.js
const confirmLink = document.getElementById('confirm');
confirmLink.addEventListener('click', (event) => {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  window.location.replace(confirmLink.href);
});
```

Render the completion page with a manual close instruction and a script that closes the sign-in tab. The original iframe still has its own **Continue in the sheet** click to request storage access. [HTML rules for script-closable windows](https://html.spec.whatwg.org/multipage/nav-history-apis.html#dom-window-close)

```html
<p>Sign-in confirmed. If this tab stays open, close it and return to the original tab.</p>
<script src="/assets/close-sign-in-tab.js" defer></script>
```

```js
// /assets/close-sign-in-tab.js
window.close();
```
