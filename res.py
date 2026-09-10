# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import json

from trytond.exceptions import LoginException
from trytond.i18n import gettext
from trytond.pool import Pool, PoolMeta
from trytond.transaction import Transaction
from webauthn import (
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from . import common


class User(metaclass=PoolMeta):
    __name__ = 'res.user'

    @classmethod
    def _login_webauthn(cls, login, parameters):
        user_id = cls._get_login(login)[0]
        payload = parameters.get('webauthn')
        if payload is None:
            if not user_id:
                return
            Credential = Pool().get('res.user.webauthn.credential')
            registered = Credential.search([('user', '=', user_id)], limit=1)
            if registered:
                purpose = 'authentication'
                type_ = 'webauthn'
                message = 'authentication_webauthn.msg_login'
            else:
                # A new authenticator proves possession, not account ownership.
                if cls._login_password(login, parameters) != user_id:
                    return
                purpose = 'registration'
                type_ = 'webauthn_registration'
                message = 'authentication_webauthn.msg_registration_required'
            descriptor = common.create_operation(cls(user_id), purpose)
            descriptor['prompt'] = gettext(message)
            raise LoginException(
                'webauthn', json.dumps(descriptor), type=type_)

        parsed = cls._parse_login_payload(payload)
        if not parsed or not user_id:
            return
        desktop_token, credential_data = parsed
        operation = common.get_operation(
            desktop_token, channel='desktop')
        if (not operation or operation.user.id != user_id
                or operation.flow != 'login'):
            return
        if (operation.purpose == 'registration'
                and cls._login_password(login, parameters) != user_id):
            return
        if operation.status == 'completed':
            if common.consume_operation(operation):
                return user_id
            return
        if operation.status != 'pending' or not credential_data:
            return
        try:
            if operation.purpose == 'registration':
                cls._store_registration(
                    user_id, operation, credential_data)
            else:
                cls._verify_authentication(
                    user_id, operation, credential_data)
        except WebAuthnException:
            cls._record_failed_attempt(operation)
            return
        if common.complete_operation(operation, consumed=True):
            return user_id
        # Verification may have stored a credential or updated its counter
        # before the challenge expired or became unavailable. A failed login
        # must not commit those changes.
        Transaction().rollback()

    @staticmethod
    def _parse_login_payload(payload):
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                return
        try:
            desktop_token = payload['desktop_token']
        except (KeyError, TypeError):
            return
        if not isinstance(desktop_token, str):
            return
        return desktop_token, payload.get('credential')

    @staticmethod
    def _record_failed_attempt(operation):
        common.record_failed_attempt(operation)

    @staticmethod
    def _parse_payload(payload):
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                return
        try:
            token = payload['challenge_id']
            credential = payload['credential']
        except (KeyError, TypeError):
            return
        if not isinstance(token, str) or not credential:
            return
        return token, credential

    @classmethod
    def _verify_authentication(cls, user_id, challenge, credential_data):
        Credential = Pool().get('res.user.webauthn.credential')
        try:
            credential_id = base64url_to_bytes(credential_data['rawId'])
        except (KeyError, TypeError, ValueError):
            raise WebAuthnException('Missing credential identifier')
        records = Credential.search([
                ('user', '=', user_id),
                ('credential_id', '=', bytes_to_base64url(credential_id)),
                ], limit=1)
        if not records:
            raise WebAuthnException('Unknown credential')
        record = records[0]
        verified = verify_authentication_response(
            credential=credential_data,
            expected_challenge=challenge.challenge,
            expected_rp_id=common.rp_id(),
            expected_origin=common.origin(),
            credential_public_key=record.credential_public_key,
            credential_current_sign_count=record.sign_count,
            require_user_verification=(
                common.verification_requirement().value == 'required'),
            )
        Credential.write([record], {
                'sign_count': verified.new_sign_count,
                'last_used_at': datetime.datetime.now(),
                })

    @classmethod
    def _store_registration(cls, user_id, challenge, credential_data, label=None):
        Credential = Pool().get('res.user.webauthn.credential')
        verified = verify_registration_response(
            credential=credential_data,
            expected_challenge=challenge.challenge,
            expected_rp_id=common.rp_id(),
            expected_origin=common.origin(),
            require_user_verification=(
                common.verification_requirement().value == 'required'),
            )
        credential_id = bytes_to_base64url(verified.credential_id)
        if Credential.search([('credential_id', '=', credential_id)], limit=1):
            raise WebAuthnException('Credential already registered')
        Credential.create([{
                'user': user_id,
                'credential_id': credential_id,
                'credential_public_key': verified.credential_public_key,
                'sign_count': verified.sign_count,
                'aaguid': verified.aaguid,
                'label': label or 'WebAuthn device',
                'created_at': datetime.datetime.now(),
                }])
