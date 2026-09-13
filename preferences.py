# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.model import fields
from trytond.model.exceptions import AccessError
from trytond.pool import Pool, PoolMeta
from trytond.transaction import Transaction, check_access
from trytond.wizard import StateAction, Wizard

from . import common


class User(metaclass=PoolMeta):
    __name__ = 'res.user'

    webauthn_keys = fields.One2Many(
        'res.user.webauthn.credential', 'user', 'Security Keys',
        help='Rename or revoke registered keys. Use Register Security Key '
        'from the Security Keys menu to enroll your own device.')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._preferences_fields.append('webauthn_keys')

    @classmethod
    def copy(cls, users, default=None):
        default = default.copy() if default else {}
        default['webauthn_keys'] = None
        return super().copy(users, default=default)

    @classmethod
    def set_preferences(cls, values):
        values = values.copy()
        commands = values.pop('webauthn_keys', [])
        user = cls._current_user()
        # set_preferences deliberately bypasses user ACLs. Do not propagate
        # that privilege to arbitrary One2Many commands or credential IDs.
        owned = {key.id for key in user.webauthn_keys}
        for command in commands:
            if command[0] == 'write':
                ids = set().union(*map(set, command[1::2]))
            elif command[0] == 'delete':
                ids = set(command[1])
            else:
                raise AccessError(gettext(
                    'authentication_webauthn.msg_credential_immutable'))
            if not ids <= owned:
                raise AccessError(gettext(
                    'authentication_webauthn.msg_credential_owner'))
        with check_access():
            cls.webauthn_keys.set(cls, 'webauthn_keys', [user.id], commands)
        super().set_preferences(values)

    @classmethod
    def _current_user(cls):
        user_id = Transaction().user
        if not user_id:
            raise UserError(gettext('authentication_webauthn.msg_no_user'))
        return cls(user_id)


class RegisterSecurityKey(Wizard):
    __name__ = 'res.user.webauthn.register'

    start = StateAction('authentication_webauthn.url_register_security_key')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls.__rpc__['execute'].fresh_session = True

    def do_start(self, action):
        # The selected record/context must never choose the enrollment owner.
        user = Pool().get('res.user')._current_user()
        operation = common.create_operation(
            user, 'registration', flow='preferences')
        action['url'] = operation['mobile_url']
        return action, {}
