# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from contextvars import ContextVar


user_agent = ContextVar('webauthn_user_agent', default='')


class UserAgentMiddleware:
    """Make the HTTP user agent available while Tryton handles a request."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        token = user_agent.set(environ.get('HTTP_USER_AGENT', '')[:512])
        try:
            return self.app(environ, start_response)
        finally:
            user_agent.reset(token)
