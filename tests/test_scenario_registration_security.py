import datetime
import hashlib
import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from proteus import Model
from werkzeug.test import Client
from webauthn.helpers import bytes_to_base64url, encode_cbor

import trytond.config as config
from trytond import security
from trytond.exceptions import LoginException, UserError
from trytond.modules.authentication_webauthn import common
from trytond.pool import Pool
from trytond.protocols.wrappers import Response
from trytond.tests.test_tryton import drop_db
from trytond.tests.tools import activate_modules
from trytond.transaction import Transaction
from trytond.wsgi import app


class TestRegistrationSecurity(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def registration_response(self, options, credential_id):
        # Emulate an ES256 authenticator with user presence and verification.
        public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        numbers = public_key.public_numbers()
        cose_key = encode_cbor({
            1: 2, 3: -7, -1: 1,
            -2: numbers.x.to_bytes(32, 'big'),
            -3: numbers.y.to_bytes(32, 'big'),
            })
        auth_data = (
            hashlib.sha256(options['rp']['id'].encode()).digest()
            + b'\x45' + bytes(4) + bytes(16)
            + len(credential_id).to_bytes(2, 'big') + credential_id + cose_key)
        client_data = json.dumps({
            'type': 'webauthn.create',
            'challenge': options['challenge'],
            'origin': common.origin(),
            }).encode()
        return {
            'id': bytes_to_base64url(credential_id),
            'rawId': bytes_to_base64url(credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': bytes_to_base64url(client_data),
                'attestationObject': bytes_to_base64url(encode_cbor({
                    'fmt': 'none', 'attStmt': {}, 'authData': auth_data,
                    })),
                },
            }

    def test(self):
        cfg = activate_modules('authentication_webauthn')
        User = Model.get('res.user')
        user = User(name='Registration security', login='registration-security')
        user.password = 'registration-test-password'
        user.save()
        database = cfg.database_name
        pool = Pool(database)
        Credential = pool.get('res.user.webauthn.credential')
        Operation = pool.get('res.user.webauthn.challenge')
        client = Client(app, Response)
        base = f'/{database}/authentication/webauthn'
        methods = config.get('session', 'authentications')
        self.addCleanup(config.set, 'session', 'authentications', methods)
        config.set('session', 'authentications', 'webauthn')

        # Knowing a login or supplying a wrong password must not grant enrollment.
        with self.assertRaises(LoginException) as missing:
            security.login(database, user.login, {}, cache=False)
        self.assertEqual(missing.exception.name, 'password')
        self.assertIsNone(security.login(
            database, user.login, {'password': 'wrong'}, cache=False))
        with Transaction().start(database, 0):
            self.assertFalse(Operation.search([('user', '=', user.id)]))

        with self.assertRaises(LoginException) as registration:
            security.login(database, user.login,
                {'password': 'registration-test-password'}, cache=False)
        self.assertEqual(registration.exception.type, 'webauthn_registration')
        descriptor = json.loads(registration.exception.message)
        options = client.get(f'{base}/desktop/options', query_string={
            'desktop_token': descriptor['desktop_token'],
            }).json['options']
        credential = self.registration_response(options, b'initial-key')
        response = client.post(f'{base}/desktop/complete', json={
            'desktop_token': descriptor['desktop_token'],
            'credential': credential,
            })
        self.assertEqual(response.status_code, 200)
        parameters = {'webauthn': {'desktop_token': descriptor['desktop_token']}}
        with self.assertRaises(LoginException) as missing:
            security.login(database, user.login, parameters, cache=False)
        self.assertEqual(missing.exception.name, 'password')
        parameters['password'] = 'wrong'
        self.assertIsNone(security.login(
            database, user.login, parameters, cache=False))
        parameters['password'] = 'registration-test-password'
        self.assertEqual(security.login(
            database, user.login, parameters, cache=False), user.id)
        self.assertIsNone(security.login(
            database, user.login, parameters, cache=False))
        with self.assertRaises(LoginException) as authentication:
            security.login(database, user.login, {}, cache=False)
        self.assertEqual(authentication.exception.type, 'webauthn')

        # Exercise real registration verification and transaction boundaries.
        # Advancing only the challenge clock reproduces expiry during verification.
        for channel in ['mobile', 'desktop', 'login', 'preferences']:
            with self.subTest(channel=channel):
                with Transaction().start(database, user.id):
                    if channel == 'preferences':
                        registration = pool.get('res.user').webauthn_registration_options()
                        options = registration['options']
                        token = registration['challenge_id']
                    else:
                        descriptor = common.create_operation(
                            pool.get('res.user')(user.id), 'registration')
                        token = descriptor['desktop_token']
                        operation = common.get_operation(token, channel='desktop')
                        options = common.registration_options(
                            operation.user, operation.challenge, [])
                    operation = common.get_operation(token, channel='desktop')
                    expiry = operation.expires_at
                credential = self.registration_response(options, channel.encode())
                with patch.object(common, 'datetime') as clock:
                    clock.datetime.now.side_effect = [
                        expiry - datetime.timedelta(seconds=1),
                        expiry + datetime.timedelta(seconds=1),
                        ]
                    if channel == 'mobile':
                        response = client.post(
                            f"{base}/qr/{descriptor['mobile_token']}/complete",
                            json={'credential': credential})
                        self.assertEqual(response.status_code, 410)
                    elif channel == 'desktop':
                        response = client.post(f'{base}/desktop/complete', json={
                            'desktop_token': token, 'credential': credential})
                        self.assertEqual(response.status_code, 410)
                    elif channel == 'login':
                        self.assertIsNone(security.login(database, user.login, {
                            'password': 'registration-test-password',
                            'webauthn': {
                                'desktop_token': token, 'credential': credential,
                                },
                            }, cache=False))
                    else:
                        with self.assertRaises(UserError):
                            with Transaction().start(database, user.id):
                                pool.get('res.user').webauthn_registration_finish({
                                    'challenge_id': token, 'credential': credential,
                                    })
                with Transaction().start(database, 0):
                    self.assertFalse(Credential.search([
                        ('credential_id', '=', credential['id']),
                        ]))
                    operation = common.get_operation(token, channel='desktop')
                    self.assertEqual(operation.status, 'pending')
                    self.assertFalse(operation.consumed)

        # A successful preference enrollment must not become a login token.
        with Transaction().start(database, user.id):
            descriptor = pool.get('res.user').webauthn_registration_qr()
        options = client.get(f'{base}/desktop/options', query_string={
            'desktop_token': descriptor['desktop_token'],
            }).json['options']
        credential = self.registration_response(options, b'preferences-key')
        response = client.post(f'{base}/desktop/complete', json={
            'desktop_token': descriptor['desktop_token'],
            'credential': credential,
            })
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(security.login(database, user.login, {
            'password': 'registration-test-password',
            'webauthn': {'desktop_token': descriptor['desktop_token']},
            }, cache=False))
        with Transaction().start(database, 0):
            self.assertEqual(len(Credential.search([
                ('user', '=', user.id),
                ])), 2)
