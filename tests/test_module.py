# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import trytond.config as config
from trytond.exceptions import LoginException
from trytond.pool import Pool
from trytond.tests import test_tryton
from trytond.tests.test_tryton import with_transaction
from trytond.transaction import Transaction

from trytond.modules.authentication_webauthn import common


class AuthenticationWebAuthnTestCase(test_tryton.ModuleTestCase):
    'Test Authentication WebAuthn module'
    module = 'authentication_webauthn'

    def setUp(self):
        super().setUp()
        methods = config.get('session', 'authentications', default='')
        config.set('session', 'authentications', 'webauthn')
        self.addCleanup(config.set, 'session', 'authentications', methods)

    def create_user(self, login='webauthn'):
        User = Pool().get('res.user')
        return User(1)

    @with_transaction()
    def test_login_requests_registration_with_password(self):
        User = Pool().get('res.user')
        Challenge = Pool().get('res.user.webauthn.challenge')
        user = self.create_user()
        User.write([user], {'password': 'registration-test-password'})

        with self.assertRaises(LoginException) as context:
            User._login_webauthn(user.login, {
                'password': 'registration-test-password',
                })

        self.assertEqual(context.exception.name, 'webauthn')
        self.assertEqual(context.exception.type, 'webauthn_registration')
        challenges = Challenge.search([
                ('user', '=', user.id),
                ('purpose', '=', 'registration'),
                ])
        self.assertEqual(len(challenges), 1)
        self.assertEqual(challenges[0].purpose, 'registration')
        self.assertEqual(challenges[0].status, 'pending')
        message = json.loads(context.exception.message)
        self.assertEqual(
            challenges[0].mobile_token_hash,
            hashlib.sha256(message['mobile_token'].encode()).hexdigest())
        self.assertNotEqual(
            challenges[0].mobile_token_hash, message['mobile_token'])

    @with_transaction()
    def test_qr_operation_stores_only_token_hashes(self):
        Operation = Pool().get('res.user.webauthn.challenge')
        user = self.create_user()

        descriptor = common.create_operation(user, 'authentication')

        operation, = Operation.search([
                ('desktop_token_hash', '=', common.hash_token(
                    descriptor['desktop_token'])),
                ])
        self.assertNotEqual(
            operation.mobile_token_hash, descriptor['mobile_token'])
        self.assertNotEqual(
            operation.desktop_token_hash, descriptor['desktop_token'])
        self.assertEqual(
            operation.mobile_token_hash,
            common.hash_token(descriptor['mobile_token']))
        self.assertEqual(
            operation.desktop_token_hash,
            common.hash_token(descriptor['desktop_token']))
        self.assertEqual(operation.status, 'pending')
        self.assertFalse(operation.consumed)

    @with_transaction()
    def test_completed_qr_operation_finishes_login_once(self):
        User = Pool().get('res.user')
        Operation = Pool().get('res.user.webauthn.challenge')
        user = self.create_user()
        descriptor = common.create_operation(user, 'authentication')
        operation = common.get_operation(
            descriptor['desktop_token'], channel='desktop')
        Operation.write([operation], {'status': 'completed'})
        payload = json.dumps({
                'desktop_token': descriptor['desktop_token'],
                })

        self.assertEqual(User._login_webauthn(user.login, {
                    'webauthn': payload,
                    }), user.id)
        self.assertTrue(operation.consumed)
        self.assertIsNone(User._login_webauthn(user.login, {
                    'webauthn': payload,
                    }))

    @with_transaction()
    def test_completed_qr_operation_expires_before_consumption(self):
        Operation = Pool().get('res.user.webauthn.challenge')
        user = self.create_user()
        descriptor = common.create_operation(user, 'authentication')
        operation = common.get_operation(
            descriptor['desktop_token'], channel='desktop')
        Operation.write([operation], {
                'status': 'completed',
                'expires_at': datetime.datetime.now() - datetime.timedelta(1),
                })

        expired = common.get_operation(
            descriptor['desktop_token'], channel='desktop')
        self.assertEqual(expired.status, 'expired')
        self.assertFalse(expired.consumed)
        self.assertFalse(common.consume_operation(expired))

    @with_transaction()
    def test_login_requests_authentication_with_credential(self):
        User = Pool().get('res.user')
        Credential = Pool().get('res.user.webauthn.credential')
        user = self.create_user()
        Credential(
            user=user,
            credential_id='credential-id',
            credential_public_key=b'public-key',
            sign_count=0,
            label='Test device',
            created_at=datetime.datetime.now(),
            ).save()

        with self.assertRaises(LoginException) as context:
            User._login_webauthn(user.login, {})

        self.assertEqual(context.exception.name, 'webauthn')
        self.assertEqual(context.exception.type, 'webauthn')

    @with_transaction()
    def test_registration_options_are_bound_to_current_user(self):
        User = Pool().get('res.user')
        user = self.create_user()

        with Transaction().set_user(user.id):
            result = User.webauthn_registration_options()

        self.assertIn('challenge_id', result)
        self.assertEqual(result['options']['rp']['id'], common.rp_id())
        self.assertEqual(result['options']['user']['name'], user.login)
        self.assertEqual(result['options']['authenticatorSelection']['userVerification'],
            'required')
        self.assertEqual(
            result['options']['authenticatorSelection']['residentKey'],
            'required')
        self.assertEqual(result['options']['hints'], ['hybrid', 'client-device'])

    def test_webauthn_settings_derive_from_web_base_url(self):
        def get(section, option, default=None):
            if section == 'web' and option == 'base_url':
                return 'https://tryton.luqueee.dev/'
            return default

        with patch.object(config, 'get', side_effect=get):
            self.assertEqual(
                common.base_url(), 'https://tryton.luqueee.dev')
            self.assertEqual(common.rp_id(), 'tryton.luqueee.dev')
            self.assertEqual(common.origin(), 'https://tryton.luqueee.dev')

    @with_transaction()
    def test_authentication_options_prefer_hybrid(self):
        result = common.authentication_options(b'challenge', [])

        self.assertEqual(result['hints'], ['hybrid', 'client-device'])

    @with_transaction()
    def test_registration_finish_stores_verified_credential(self):
        User = Pool().get('res.user')
        Credential = Pool().get('res.user.webauthn.credential')
        user = self.create_user()
        verified = SimpleNamespace(
            credential_id=b'credential-id',
            credential_public_key=b'public-key',
            sign_count=0,
            aaguid='00000000-0000-0000-0000-000000000000',
            user_verified=True,
            )

        with Transaction().set_user(user.id):
            options = User.webauthn_registration_options()
            payload = {
                'challenge_id': options['challenge_id'],
                'credential': {'id': 'credential-id'},
                }
            with patch(
                    'trytond.modules.authentication_webauthn.res.'
                    'verify_registration_response',
                    return_value=verified):
                result = User.webauthn_registration_finish(payload)

        self.assertEqual(result['status'], 'ok')
        credentials = Credential.search([('user', '=', user.id)])
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0].credential_public_key, b'public-key')
