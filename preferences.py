# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.model import ModelView, fields
from trytond.model.exceptions import AccessError
from trytond.pool import Pool, PoolMeta
from trytond.rpc import RPC
from trytond.transaction import Transaction, check_access
from trytond.wizard import StateAction, Wizard

from . import common


class User(metaclass=PoolMeta):
    __name__ = 'res.user'

    webauthn_keys = fields.One2Many(
        'res.user.webauthn.credential', 'user', 'Security Keys',
        help='Rename or revoke registered keys. Use Register Security Key '
        'to enroll your own device.')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._preferences_fields.append('webauthn_keys')
        cls._buttons.update({
            'register_security_key': {},
            })
        # Preference forms must allow this action without res.user write ACL.
        cls.__rpc__['register_security_key'] = RPC(
            readonly=False, instantiate=0, check_access=False)

    @classmethod
    @ModelView.button_action('authentication_webauthn.act_register_security_key')
    def register_security_key(cls, users):
        pass

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

    @classmethod
    def check_access(cls):
        # The wizard registers only the authenticated user, not active records.
        transaction = Transaction()
        context = transaction.context
        active_ids = set(context.get('active_ids') or [])
        if (
                context.get('active_model') == 'res.user'
                and context.get('active_id') == transaction.user
                and active_ids == {transaction.user}):
            with transaction.set_context(
                    active_model=None, active_id=None, active_ids=None):
                return super().check_access()
        return super().check_access()

    def do_start(self, action):
        # The selected record/context must never choose the enrollment owner.
        user = Pool().get('res.user')._current_user()
        operation = common.create_operation(
            user, 'registration', flow='preferences')
        action['url'] = (
            f"{operation['mobile_url']}#desktop_token="
            f"{operation['desktop_token']}")
        return action, {}
