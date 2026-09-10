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

After the password is accepted, Tryton creates a short-lived, single-use QR
operation. Only SHA-256 token hashes are stored. The mobile page performs
``navigator.credentials.create`` or ``navigator.credentials.get`` and the
desktop polls the operation until it is completed. USB FIDO2 and local browser
WebAuthn remain available as alternatives from the QR dialog.
