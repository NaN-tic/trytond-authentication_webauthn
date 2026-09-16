import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

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


class TestWebHostname(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        cfg = activate_modules('authentication_webauthn')
        User = Model.get('res.user')
        user = User(name='Web hostname', login='web-hostname')
        user.save()
        pool = Pool(cfg.database_name)
        client = Client(app, Response)
        original_get = config.get
        settings = {
            ('web', 'base_url'): '',
            ('web', 'hostname'): 'tryton.example.com:8443',
            ('ssl', 'certificate'): '',
            ('ssl', 'privatekey'): '',
            }

        def get(section, option, *args, **kwargs):
            if (section, option) in settings:
                return settings[section, option]
            return original_get(section, option, *args, **kwargs)

        with patch.object(config, 'get', side_effect=get):
            for secure in [False, True]:
                scheme = 'https' if secure else 'http'
                expected = f'{scheme}://tryton.example.com:8443'
                request = {
                    'http_host': 'internal.example.com:8000',
                    'is_secure': secure,
                    'scheme': scheme,
                    }
                with self.subTest(secure=secure):
                    with Transaction().start(cfg.database_name, user.id,
                            context={'_request': request}):
                        descriptor = common.create_operation(
                            pool.get('res.user')(user.id), 'registration')
                        self.assertEqual(common.base_url(), expected)
                        self.assertEqual(common.base_url(request), expected)
                        self.assertEqual(common.origin(), expected)
                        self.assertEqual(common.rp_id(), 'tryton.example.com')
                    self.assertTrue(descriptor['mobile_url'].startswith(
                        expected + '/'))
                    response = client.get(
                        urlsplit(descriptor['mobile_url']).path + '/options',
                        base_url=expected)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json['options']['rp']['id'],
                        'tryton.example.com')

            with Transaction().start(cfg.database_name, user.id):
                for option in ['certificate', 'privatekey']:
                    with self.subTest(ssl=option):
                        settings['ssl', option] = 'configured.pem'
                        self.assertEqual(common.origin(),
                            'https://tryton.example.com:8443')
                        self.assertEqual(common.rp_id(), 'tryton.example.com')
                        settings['ssl', option] = ''

                settings['web', 'base_url'] = 'https://public.example.com/'
                self.assertEqual(common.base_url(request),
                    'https://public.example.com')
                self.assertEqual(common.rp_id(), 'public.example.com')
                self.assertEqual(common.origin(), 'https://public.example.com')

                settings['web', 'base_url'] = ''
                settings['web', 'hostname'] = ''
                with Transaction().set_context(_request=request):
                    self.assertEqual(common.base_url(),
                        'https://internal.example.com:8000')
                    self.assertEqual(common.rp_id(), 'internal.example.com')
                    self.assertEqual(common.origin(),
                        'https://internal.example.com:8000')
