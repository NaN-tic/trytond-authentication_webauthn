# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.wsgi import app

from . import routes
from .wsgi import UserAgentMiddleware

app.wsgi_app = UserAgentMiddleware(app.wsgi_app)

__all__ = ['routes']
