# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import json
from http import HTTPStatus
from unittest.mock import patch

from trytond.pool import Pool
from trytond.tests import test_tryton
from trytond.transaction import Transaction

from trytond.modules.authentication_webauthn import common


class AuthenticationWebAuthnRouteTestCase(test_tryton.RouteTestCase):
    "Test Authentication WebAuthn routes"
    module = 'authentication_webauthn'

    def create_operation(self, purpose='authentication'):
        with Transaction().start(self.db_name, 1):
            user = Pool().get('res.user')(1)
            descriptor = common.create_operation(user, purpose)
        return descriptor

    def url(self, endpoint):
        return f'{self.db_name}/authentication/webauthn/{endpoint}'

    def test_desktop_status_and_cancel(self):
        descriptor = self.create_operation()
        client = self.client()

        response = client.get(
            self.url('desktop/status'),
            query_string={'desktop_token': descriptor['desktop_token']})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json['status'], 'pending')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

        response = client.post(
            self.url('desktop/cancel'),
            data=json.dumps({'desktop_token': descriptor['desktop_token']}),
            content_type='application/json')
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json, {'status': 'cancelled'})

        response = client.get(
            self.url('desktop/status'),
            query_string={'desktop_token': descriptor['desktop_token']})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json['status'], 'cancelled')

    def test_desktop_options_and_missing_credential(self):
        descriptor = self.create_operation()
        client = self.client()

        response = client.get(
            self.url('desktop/options'),
            query_string={'desktop_token': descriptor['desktop_token']})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json['purpose'], 'authentication')
        self.assertIn('challenge', response.json['options'])

        response = client.post(
            self.url('desktop/complete'),
            data=json.dumps({'desktop_token': descriptor['desktop_token']}),
            content_type='application/json')
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(
            response.json, {'error': 'A WebAuthn credential is required.'})

    def test_mobile_page_and_qr_code(self):
        descriptor = self.create_operation()
        client = self.client()

        response = client.get(self.url(
            f"qr/{descriptor['mobile_token']}"))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn('text/html', response.content_type)
        self.assertIn('Approve access', response.text)

        response = client.get(self.url(
            f"qr-code/{descriptor['mobile_token']}.svg"))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.mimetype, 'image/svg+xml')
        self.assertIn(b'<svg', response.data)

    def test_mobile_complete_marks_operation_completed(self):
        descriptor = self.create_operation()
        client = self.client()
        credential = {'rawId': 'credential-id'}

        with patch(
                'trytond.modules.authentication_webauthn.res.User.'
                '_verify_authentication'):
            response = client.post(
                self.url(f"qr/{descriptor['mobile_token']}/complete"),
                data=json.dumps({'credential': credential}),
                content_type='application/json')
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json, {'status': 'approved'})
        response = client.get(
            self.url('desktop/status'),
            query_string={'desktop_token': descriptor['desktop_token']})
        self.assertEqual(response.json['status'], 'completed')
