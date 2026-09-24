import unittest

from proteus import Model
from werkzeug.test import Client
from webauthn.helpers.exceptions import WebAuthnException

from trytond.modules.authentication_webauthn import common
from trytond.pool import Pool
from trytond.protocols.wrappers import Response
from trytond.tests.test_tryton import drop_db
from trytond.tests.tools import activate_modules
from trytond.transaction import Transaction
from trytond.wsgi import app


class TestInputTypes(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        cfg = activate_modules('authentication_webauthn')
        User = Model.get('res.user')
        user = User(name='Input types', login='input-types')
        user.save()
        pool = Pool(cfg.database_name)
        ServerUser = pool.get('res.user')
        client = Client(app, Response)
        base = f'/{cfg.database_name}/authentication/webauthn'
        with Transaction().start(cfg.database_name, user.id):
            descriptor = common.create_operation(
                ServerUser(user.id), 'registration')
        for value in [None, 1234, True, ['token'], {'token': 'bad'}]:
            with self.subTest(token=value):
                for action in ['complete', 'regenerate', 'cancel']:
                    response = client.post(f'{base}/desktop/{action}', json={
                        'desktop_token': value,
                        })
                    self.assertEqual(response.status_code, 404)
        for value in [None, 1234, True, ['bad'], 'bad']:
            with self.subTest(payload=value):
                for path in ['desktop/complete', 'desktop/regenerate',
                        'desktop/cancel',
                        f"qr/{descriptor['mobile_token']}/complete"]:
                    response = client.post(f'{base}/{path}', json=value)
                    self.assertEqual(response.status_code, 400)
        with Transaction().start(cfg.database_name, user.id):
            operation = common.get_operation(
                descriptor['desktop_token'], channel='desktop')
            self.assertEqual(operation.status, 'pending')
            for value in [None, 1234, True, ['bad']]:
                with self.subTest(credential=value):
                    with self.assertRaises(WebAuthnException):
                        ServerUser._store_registration(user.id, operation, value)
                    with self.assertRaises(WebAuthnException):
                        ServerUser._verify_authentication(user.id, operation,
                            {'rawId': value})
            self.assertFalse(pool.get('res.user.webauthn.credential').search([
                ('user', '=', user.id),
                ]))
