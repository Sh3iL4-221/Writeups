# thryveCTF 2026 — Sketchy

## Summary

*Sketchy* chains exposed static files, weakly hidden administrative credentials,
a predictable 2FA value in a session cookie, and an authenticated WebSocket
feature.  The final action is to have the sketch-recognition service recognise
`cat flag.txt`, then save it; the backend executes that recognised text and
returns the flag.

> The instance used while testing did not establish the expected WebSocket
> connection, so the final flag value is not recorded here.  The intended
> payload and exploit path are nevertheless reproducible from the JavaScript.

## 1. Reconnaissance

Start by fetching the root page and noting the web server and page name:

```bash
curl -i http://TARGET/
```

The response is served by nginx and refers to `public.html`.  Checking common
files and static paths reveals the administrative area:

```bash
curl http://TARGET/robots.txt
# User-agent: *
# Disallow: /admin

curl http://TARGET/static/
```

The static directory exposes `index.html`, which points to the non-public
script, `/static/script.js`.

## 2. Recover the administrator password

Viewing the source of `/` exposes two useful clues:

```html
<!-- hktpu:GqD2lEki6WOe32GNBiD8EDrDfGMLJU -->
<script src="/static/script-public.js"></script>
```

`hktpu` is `admin` under a Caesar shift of -7.  Applying that same shift to
the value after the colon gives the credentials:

```text
admin:ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN
```

Use them at `/admin`.

## 3. Bypass / understand the 2FA step

The login-page source contains another hint:

```html
<!-- c291cA== -->
```

Base64-decoding it yields `soup`:

```bash
printf '%s' c291cA== | base64 -d
# soup
```

After the administrator login, inspect the cookie issued for the 2FA page.
The example session is an `itsdangerous`/Flask-style signed value:

```text
eyJvdHAiOiI1Njk2IiwidXNlciI6ImFkbWluIn0.aoSLXg.Hz_S7_d6bykGmQdwR2I0UtP12TQ
```

Only decode the first dot-separated segment (with Base64 padding restored):

```bash
printf '%s' 'eyJvdHAiOiI1Njk2IiwidXNlciI6ImFkbWluIn0=' | base64 -d
# {"otp":"5696","user":"admin"}
```

Enter `5696` as the OTP.  The `soup` hint is also a strong indication that the
Flask session signing secret is exposed; it would allow a forged session if
the application required one.  In this run, the valid OTP was already present
in the server-issued cookie, so no forgery was necessary.

## 4. Reach the authenticated drawing application

The public landing page loads `/static/script-public.js`, where saving is
deliberately disabled.  That explains the alert:

```text
Saving is currently disabled for maintenance.
```

It also explains why no WebSocket is created on the public page.  After
authentication, the application loads the real `/static/script.js`.  Its
important logic is:

```js
const ws = new WebSocket(`${protocol}//${location.host}/ws`);

// Canvas coordinates are sent while drawing.
ws.send(JSON.stringify({ x, y, drawing: isDrawing }));

// Saving sends a distinct message.
ws.send(JSON.stringify({ type: 'save' }));
```

The server returns recognised canvas text as `{"type":"recognized", ...}`
and returns the result of a save as `{"type":"save_result", ...}`.  The
client does not itself execute commands; the vulnerable behaviour is server
side, in the recognition/save service.

## 5. Trigger the command execution

On the authenticated sketch page:

1. Draw the text `cat flag.txt` clearly on the canvas.
2. Confirm that the recognised-text field reads `cat flag.txt`.
3. Click **Save**.
4. Read the flag from the save-result field (or the WebSocket response in the
   browser Network → WS panel).

The successful WebSocket sequence conceptually looks like:

```text
client → /ws: drawing coordinate messages
server → client: {"type":"recognized", "text":"cat flag.txt"}
client → /ws: {"type":"save"}
server → client: {"type":"save_result", "result":"<flag>"}
```

## Why the initial attempt failed

Drawing on `/` cannot work: `script-public.js` intentionally disables saving
and does not open `/ws`.  Changing colour or brush size only affects the local
canvas and cannot enable the server feature.  The exploit must be performed
after completing the `/admin` login and OTP flow, on the page that loads the
real `script.js`.

If the authenticated page still has no WebSocket request, check that the
browser retained the login/2FA cookies and that the page source references
`/static/script.js` rather than `/static/script-public.js`.  A dead challenge
instance will also prevent `/ws` from connecting; that is infrastructure
failure, not a different payload.

## Quick summary

```text
GET /
  → inspect headers/source and enumerate robots.txt/static files
  → find the Caesar-shifted admin credential in an HTML comment
  → decode the second HTML comment (`c291cA==` → `soup`)
  → log in at /admin
  → inspect the session cookie and submit OTP 5696
  → load the authenticated page and verify /static/script.js
  → connect to /ws
  → draw `cat flag.txt`
  → send Save and read the save_result response
```

## Reusable exploit guidelines

For similar challenges, the following workflow is useful:

1. **Establish a baseline.** Record the status code, headers, redirects,
   cookies, and linked assets from `/` before interacting with the UI. Keep a
   transcript of each request so a later redirect or cookie change is visible.
2. **Enumerate low-cost files first.** Check `robots.txt`, common HTML names,
   JavaScript and CSS directories, source maps, favicons, and backup suffixes.
   `robots.txt` is not access control; a disallowed path is often an invitation
   to inspect it.
3. **Read every client-side asset.** Search HTML comments and JavaScript for
   endpoints, feature flags, disabled functionality, WebSocket URLs, message
   types, and hidden routes. Compare public and authenticated versions of the
   same page.
4. **Treat clues as transformations.** Test obvious encodings in a sensible
   order—Base64, URL encoding, hexadecimal, and Caesar/ROT shifts—and verify
   that the decoded result is meaningful before using it as a credential.
5. **Inspect cookies carefully.** Split structured cookies on `.` and decode
   only the data segment. Base64 decoding reveals contents but does not prove
   that a cookie can be modified: signed cookies require the correct secret and
   signing algorithm. Never paste a real session token into third-party tools.
6. **Separate UI behavior from server behavior.** A disabled button, alert, or
   missing request may be an intentional public-page restriction. Confirm the
   loaded script, authentication state, and actual network request before
   changing the payload.
7. **Debug WebSockets in the Network panel.** Confirm the `101 Switching
   Protocols` handshake, inspect the exact direction and JSON of each frame,
   and check console errors and cookie scope. If there is no handshake, debug
   page state or connectivity first; drawing more input will not fix a socket
   that was never opened.
8. **Use the smallest proof payload.** Once the protocol is understood, send
   the minimum command or input needed to demonstrate impact. Capture the
   server response as evidence, and redact unrelated credentials from the
   final writeup.

## Capturing the WebSocket

### Browser DevTools

Chrome/Chromium is enough to observe the connection:

1. Open DevTools (`F12`) before loading the authenticated page.
2. Select **Network**, enable **Preserve log**, and choose the **WS** filter.
3. Reload the page. The request should be `ws://TARGET/ws` (or `wss://...` for
   HTTPS), with a successful `101 Switching Protocols` response.
4. Click the `/ws` request and open **Messages**. Outgoing frames are shown in
   green and incoming frames in white. Draw on the canvas and click Save while
   this panel is open.
5. Save the frames containing `recognized` and `save_result` for the writeup.

If `/ws` is absent, reload after opening DevTools. Also verify that the page
loaded `/static/script.js`, that the browser still has the authenticated
cookies, and that the console does not show a WebSocket error. The browser
usually provides the quickest visual confirmation, but is less convenient for
editing or replaying frames. Chrome's Network panel documents the WS filter
and Messages view. [Chrome DevTools WebSocket inspection](https://developer.chrome.com/docs/devtools/network/reference/?hl=en)

### Burp Suite (recommended for this challenge)

Burp is more useful when you need a complete record or want to replay the
protocol:

1. Start Burp and use **Proxy → Open Browser**, or configure the normal
   browser to use Burp's proxy listener (normally `127.0.0.1:8080`). Install
   Burp's CA certificate only in a dedicated testing profile if HTTPS is used.
2. Add the challenge host to the Burp scope. Leave WebSocket interception off
   initially so frames are not paused.
3. Complete login and 2FA in Burp's browser, then open the authenticated sketch
   page and draw once.
4. Go to **Proxy → WebSockets history** and select the `/ws` connection. The
   table records direction, URL, connection ID, and each frame. Search for
   `recognized`, `save`, or `save_result`.
5. To test a frame manually, right-click it and choose **Send to Repeater**.
   In Repeater, preserve the session cookies, edit the JSON, and click **Send**.
   The connection must still be open to send a message directly to it.

Burp's WebSockets history continues recording even when interception is off,
and its Repeater workflow supports modifying and resending frames. [Burp WebSockets history](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
and [Burp WebSocket Repeater](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/websockets/manipulating-websocket-messages)
are the relevant references.

For this challenge, use DevTools to confirm that `/ws` exists and Burp to
capture the exact frames and preserve the final `save_result` response. Do not
send the same save command repeatedly against a live instance unless needed;
one clean request/response pair is sufficient evidence.
