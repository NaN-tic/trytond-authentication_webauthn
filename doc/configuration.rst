*************
Configuration
*************

The *Authentication WebAuthn Module* adds the ``webauthn`` authentication
method. It can be combined with the password method using::

    [session]
    authentications = password+webauthn

The relying-party settings are read from ``[authentication_webauthn]``::

    [authentication_webauthn]
    rp_name = Tryton
    user_verification = required
    timeout = 60000
    challenge_ttl = 120
    max_attempts = 5

Configure the public URL once in the web section::

    [web]
    base_url = https://tryton.empresa.local

The URL used by the browser is read from ``[web] base_url``. The WebAuthn
``rp_id`` is derived from its host and the expected ``origin`` from its scheme,
host and port. The same HTTPS ``base_url`` must be reachable by both the
desktop and mobile browsers in production. ``rp_name`` is the optional name
displayed by the authenticator during registration and defaults to ``Tryton``.

``user_verification`` controls whether the authenticator must verify the user:
``required`` enforces biometrics, a PIN or device unlock; ``preferred`` asks
for verification when available; and ``discouraged`` does not request it.

Initial registration during login always requires the account password,
including when ``authentications = webauthn`` is used alone. The password is
checked both when starting registration and when finishing the login. Accounts
without a usable password must enroll from an already authenticated session
using preferences. Preference registration operations cannot complete a login.
Once a credential is enrolled, WebAuthn-only login does not require a password.

After the password is accepted, Tryton creates a short-lived, single-use QR
operation. Only SHA-256 token hashes are stored. The mobile page performs
``navigator.credentials.create`` or ``navigator.credentials.get`` and the
desktop polls the operation until it is completed. USB FIDO2 and local browser
WebAuthn remain available as alternatives from the QR dialog.

The mobile confirmation page displays the initiating connection's IP address
and a readable browser name, major version and operating system, inferred from
the reported User-Agent. The full User-Agent is available under technical
details.
The module captures the User-Agent through its own WSGI middleware, without
requiring changes to Tryton's request context, and stores at most 512 characters.
Unrecognized browsers or systems display "Not available"; operating
system versions are omitted because browsers may report reduced or frozen
versions. These details are preserved when the QR
is regenerated. The browser information is untrusted and is shown as a hint,
not as proof of device identity. The IP address comes from Tryton's request
context; deployments behind a reverse proxy must configure ``[web] num_proxies``
for their trusted proxy chain. Existing operations without browser information
display "Not available".

The page also shows the operation's creation date and time in the phone's
local time zone, including the zone label. The server supplies UTC as a
fallback. Regenerating a QR creates a new operation with a new timestamp.
