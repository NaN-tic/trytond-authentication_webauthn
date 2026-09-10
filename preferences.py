# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.pool import Pool, PoolMeta
from trytond.rpc import RPC
from trytond.transaction import Transaction
from webauthn.helpers.exceptions import WebAuthnException

from . import common


class User(metaclass=PoolMeta):
    __name__ = 'res.user'

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls.__rpc__.update({
                'webauthn_registration_options': RPC(
                    readonly=False, check_access=False),
                'webauthn_registration_finish': RPC(
                    readonly=False, check_access=False),
                'webauthn_registration_qr': RPC(
                    readonly=False, check_access=False),
                'webauthn_credentials': RPC(check_access=False),
                'webauthn_rename': RPC(
                    readonly=False, check_access=False),
                'webauthn_revoke': RPC(
                    readonly=False, check_access=False),
                })

    @classmethod
    def _current_user(cls):
        user_id = Transaction().user
        if not user_id:
            raise UserError(gettext('authentication_webauthn.msg_no_user'))
        return cls(user_id)

    @classmethod
    def webauthn_registration_options(cls):
        user = cls._current_user()
        Credential = Pool().get('res.user.webauthn.credential')
        token, challenge = common.create_challenge(user.id, 'registration')
        credentials = Credential.search([('user', '=', user.id)])
        return {
            'challenge_id': token,
            'options': common.registration_options(
                user, challenge, credentials),
            }

    @classmethod
    def webauthn_registration_finish(cls, payload, label=None):
        user = cls._current_user()
        parsed = cls._parse_payload(payload)
        if not parsed:
            raise UserError(gettext(
                'authentication_webauthn.msg_invalid_response'))
        token, credential_data = parsed
        challenge = common.get_challenge(user.id, token, 'registration')
        if not challenge:
            raise UserError(gettext(
                'authentication_webauthn.msg_invalid_response'))
        try:
            cls._store_registration(
                user.id, challenge, credential_data, label=label)
        except WebAuthnException as exception:
            raise UserError(gettext(
                'authentication_webauthn.msg_invalid_response')) from exception
        if not common.complete_operation(challenge, consumed=True):
            raise UserError(gettext(
                'authentication_webauthn.msg_invalid_response'))
        return {'status': 'ok'}

    @classmethod
    def webauthn_registration_qr(cls):
        return common.create_operation(
            cls._current_user(), 'registration', flow='preferences')

    @classmethod
    def webauthn_credentials(cls):
        user = cls._current_user()
        Credential = Pool().get('res.user.webauthn.credential')
        credentials = Credential.search(
            [('user', '=', user.id)], order=[('created_at', 'ASC')])
        count = len(credentials)
        return [
            {
                'id': credential.credential_id,
                'label': credential.label,
                'created_at': credential.created_at.isoformat(),
                'last_used_at': (
                    credential.last_used_at.isoformat()
                    if credential.last_used_at else None),
                'is_last': count == 1,
                }
            for credential in credentials]

    @classmethod
    def webauthn_rename(cls, credential_id, label):
        user = cls._current_user()
        label = label.strip()
        if not label:
            raise UserError(gettext(
                'authentication_webauthn.msg_invalid_label'))
        Credential = Pool().get('res.user.webauthn.credential')
        records = Credential.search([
                ('user', '=', user.id),
                ('credential_id', '=', credential_id),
                ], limit=1)
        if records:
            Credential.write(records, {'label': label})

    @classmethod
    def webauthn_revoke(cls, credential_id, confirm_last=False):
        user = cls._current_user()
        Credential = Pool().get('res.user.webauthn.credential')
        credentials = Credential.search([('user', '=', user.id)])
        records = [credential for credential in credentials
            if credential.credential_id == credential_id]
        if records:
            if len(credentials) == 1 and not confirm_last:
                raise UserError(gettext(
                    'authentication_webauthn.msg_confirm_last'))
            Credential.delete(records)
