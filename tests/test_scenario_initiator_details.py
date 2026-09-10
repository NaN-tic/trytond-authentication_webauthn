import json
import unittest
from html import escape

from proteus import Model
from werkzeug.test import Client

import trytond.config as config
from trytond.modules.authentication_webauthn import common
from trytond.pool import Pool
from trytond.protocols.wrappers import Response
from trytond.tests.test_tryton import drop_db
from trytond.tests.tools import activate_modules
from trytond.transaction import Transaction
from trytond.wsgi import app


class TestInitiatorDetails(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        cfg = activate_modules('authentication_webauthn')
        User = Model.get('res.user')
        user = User(name='Initiator details', login='initiator-details')
        user.password = 'initiator-test-password'
        user.save()
        methods = config.get('session', 'authentications')
        self.addCleanup(config.set, 'session', 'authentications', methods)
        config.set('session', 'authentications', 'password+webauthn')
        client = Client(app, Response)
        database = cfg.database_name
        base = f'/{database}/authentication/webauthn'
        browser = ('Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0 '
            '<script>alert(1)</script> __JS__')

        # Go through HTTP login so metadata must come from Request.context.
        response = client.post(f'/{database}/rpc/', json={
            'id': 1, 'method': 'common.db.login',
            'params': [user.login, {'password': 'initiator-test-password'}],
            }, headers={'User-Agent': browser},
            environ_overrides={'REMOTE_ADDR': '192.0.2.10'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['error'][0], 'LoginException')
        descriptor = json.loads(response.json['error'][1][1])
        with Transaction().start(database, 0):
            operation = common.get_operation(
                descriptor['desktop_token'], channel='desktop')
            self.assertEqual(operation.initiator, '192.0.2.10')
            self.assertEqual(operation.initiator_user_agent, browser)
            requested_at = operation.created_at

        response = client.get(
            f"{base}/qr/{descriptor['mobile_token']}",
            headers={'User-Agent': 'Mobile Safari'},
            environ_overrides={'REMOTE_ADDR': '198.51.100.20'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('192.0.2.10', response.text)
        self.assertIn(escape(browser), response.text)
        self.assertIn('<dd>Firefox 140</dd>', response.text)
        self.assertIn('<dd>Linux</dd>', response.text)
        self.assertIn(
            f'datetime="{requested_at.isoformat()}Z"', response.text)
        self.assertIn(
            requested_at.strftime('%Y-%m-%d %H:%M:%S UTC'), response.text)
        self.assertNotIn('<script>alert(1)</script>', response.text)
        self.assertNotIn('198.51.100.20', response.text)
        self.assertNotIn('Mobile Safari', response.text)
        self.assertIn('Only confirm if you initiated this request', response.text)

        response = client.post(f'{base}/desktop/regenerate', json={
            'desktop_token': descriptor['desktop_token'],
            }, headers={'User-Agent': 'Another browser'},
            environ_overrides={'REMOTE_ADDR': '203.0.113.30'})
        self.assertEqual(response.status_code, 200)
        regenerated = response.json
        with Transaction().start(database, 0):
            operation = common.get_operation(
                regenerated['desktop_token'], channel='desktop')
            regenerated_at = operation.created_at
            self.assertGreaterEqual(regenerated_at, requested_at)
        response = client.get(f"{base}/qr/{regenerated['mobile_token']}")
        self.assertEqual(response.status_code, 200)
        self.assertIn('192.0.2.10', response.text)
        self.assertIn(escape(browser), response.text)
        self.assertIn(
            f'datetime="{regenerated_at.isoformat()}Z"', response.text)
        self.assertNotIn('203.0.113.30', response.text)
        self.assertNotIn('Another browser', response.text)

        # Missing metadata remains readable for existing and non-HTTP requests.
        with Transaction().start(database, user.id):
            descriptor = common.create_operation(
                Pool().get('res.user')(user.id), 'registration',
                flow='preferences')
        response = client.get(f"{base}/qr/{descriptor['mobile_token']}")
        self.assertEqual(response.status_code, 200)
        self.assertIn('Not available', response.text)

        response = client.post(f'/{database}/rpc/', json={
            'id': 2, 'method': 'common.db.login',
            'params': [user.login, {'password': 'initiator-test-password'}],
            }, headers={'User-Agent': 'x' * 1024})
        descriptor = json.loads(response.json['error'][1][1])
        with Transaction().start(database, 0):
            operation = common.get_operation(
                descriptor['desktop_token'], channel='desktop')
            self.assertEqual(operation.initiator_user_agent, 'x' * 512)

        for agent, browser_name, os_name in [
                ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0',
                    'Edge 143', 'Windows'),
                ('Mozilla/5.0 (Windows NT 10.0) '
                    'Chrome/143.0.0.0 Safari/537.36', 'Chrome 143', 'Windows'),
                ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                    'Version/18.3 Safari/605.1.15', 'Safari 18', 'macOS'),
                ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) '
                    'CriOS/140.0 Mobile/15E148 Safari/604.1',
                    'Chrome 140', 'iOS / iPadOS'),
                ('Mozilla/5.0 (Linux; Android 10; K) '
                    'SamsungBrowser/28.0 Chrome/130.0 Safari/537.36',
                    'Samsung Internet 28', 'Android'),
                ('Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) '
                    'Chrome/143.0 Safari/537.36', 'Chrome 143', 'ChromeOS'),
                ('Mozilla/5.0 (X11; Linux x86_64) '
                    'Chrome/139.0 Safari/537.36 OPR/124.0',
                    'Opera 124', 'Linux'),
                ('Custom client', 'Not available', 'Not available'),
                ]:
            with self.subTest(agent=agent):
                with Transaction().start(database, user.id, context={
                        '_request': {'user_agent': agent},
                        }):
                    descriptor = common.create_operation(
                        Pool().get('res.user')(user.id), 'registration',
                        flow='preferences')
                response = client.get(
                    f"{base}/qr/{descriptor['mobile_token']}")
                self.assertEqual(response.status_code, 200)
                self.assertIn(f'<dd>{browser_name}</dd>', response.text)
                self.assertIn(f'<dd>{os_name}</dd>', response.text)
                self.assertIn(escape(agent), response.text)
