import datetime
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree
from proteus import Model, Wizard
from webauthn.helpers import bytes_to_base64url, encode_cbor
from werkzeug.test import Client

from trytond.exceptions import UserError, UserWarning
from trytond.model.exceptions import AccessError
from trytond.modules.authentication_webauthn import common
from trytond.pool import Pool
from trytond.protocols.wrappers import Response
from trytond.tests.test_tryton import drop_db
from trytond.tests.tools import activate_modules
from trytond.transaction import Transaction
from trytond.wsgi import app


class TestKeyManagement(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def register(self, cfg, credential_id):
        wizard = Wizard('res.user.webauthn.register')
        url, = wizard.actions
        mobile_url = url.split('#', 1)[0]
        client = Client(app, Response)
        self.assertEqual(client.get(mobile_url).status_code, 200)
        response = client.get(mobile_url + '/options')
        self.assertEqual(response.status_code, 200)
        options = response.json['options']
        rp_id = options['rp']['id']
        user_handle = hashlib.sha256(
            f'{rp_id}:{cfg.user}'.encode('utf-8')).digest()
        self.assertEqual(
            options['user']['id'], bytes_to_base64url(user_handle))
        self.assertEqual(response.json['rp_id'], rp_id)
        self.assertEqual(options['authenticatorSelection']['userVerification'],
            'required')
        self.assertEqual(options['authenticatorSelection']['residentKey'],
            'required')
        self.assertEqual(options['hints'], ['hybrid', 'client-device'])
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
        credential = {
            'id': bytes_to_base64url(credential_id),
            'rawId': bytes_to_base64url(credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': bytes_to_base64url(json.dumps({
                    'type': 'webauthn.create',
                    'challenge': options['challenge'],
                    'origin': response.request.host_url.rstrip('/'),
                    }).encode()),
                'attestationObject': bytes_to_base64url(encode_cbor({
                    'fmt': 'none', 'attStmt': {}, 'authData': auth_data,
                    })),
                },
            }
        response = client.post(mobile_url + '/complete', json={
            'credential': credential,
            })
        self.assertEqual(response.status_code, 200)
        Credential = Model.get('res.user.webauthn.credential')
        key, = Credential.find([('credential_id', '=', credential['id'])])
        self.assertEqual(key.user.id, cfg.user)
        return key.id

    def test(self):
        cfg = activate_modules('authentication_webauthn')
        cfg.skip_warning = False
        admin = cfg.user
        User = Model.get('res.user')
        alice = User(name='Alice', login='alice')
        alice.save()
        bob = User(name='Bob', login='bob')
        bob.save()
        Credential = Model.get('res.user.webauthn.credential')
        keys = cfg.get_proxy('res.user.webauthn.credential')
        users = cfg.get_proxy('res.user')
        challenges = cfg.get_proxy('res.user.webauthn.challenge')
        pool = Pool(cfg.database_name)

        cfg.user = alice.id
        # Enrollment and key management no longer expose custom user RPCs.
        for method in [
                'webauthn_registration_options', 'webauthn_registration_finish',
                'webauthn_registration_qr', 'webauthn_credentials',
                'webauthn_rename', 'webauthn_revoke']:
            with self.subTest(method=method):
                self.assertNotIn(method, pool.get('res.user').__rpc__)
                with self.assertRaisesRegex(TypeError, 'is not callable'):
                    getattr(users, method)({})
        alice_key = self.register(cfg, b'alice-key')
        backup = self.register(cfg, b'alice-backup')
        prefs = users.get_preferences(False, {})
        self.assertEqual(set(prefs['webauthn_keys']), {alice_key, backup})
        view = users.get_preferences_fields_view({})
        preferences_arch = etree.fromstring(view['arch'])
        self.assertTrue(preferences_arch.xpath(
            '//page[@name="webauthn_keys"]/'
            'button[@name="register_security_key"]'))
        self.assertTrue(preferences_arch.xpath(
            '//page[@name="webauthn_keys"]/field[@name="webauthn_keys"]'))
        self.assertFalse(view['fields']['webauthn_keys']['readonly'])

        registration = User.click([alice], 'register_security_key')
        self.assertIsInstance(registration, Wizard)
        self.assertEqual(registration.name, 'res.user.webauthn.register')
        registration._proxy.delete(
            registration.session_id, registration._context)
        for type_ in ['tree', 'form']:
            view = keys.fields_view_get(None, type_, {})
            self.assertIn('label', view['fields'])
            self.assertTrue(view['fields']['user']['readonly'])

        # Rename through both the ordinary form and the preferences RPC.
        key = Credential(alice_key)
        key.label = ' Laptop '
        key.save()
        self.assertEqual(Credential(alice_key).label, 'Laptop')
        users.set_preferences({'webauthn_keys': [
            ('write', [alice_key], {'label': 'Personal key'})]}, {})
        self.assertEqual(Credential(alice_key).label, 'Personal key')
        with self.assertRaises(UserError):
            keys.write([alice_key], {'label': '   '}, {})

        # A second user with identical groups must get a distinct rule cache.
        cfg.user = bob.id
        bob_key = self.register(cfg, b'bob-key')
        self.assertEqual(keys.search([], 0, None, None, {}), [bob_key])
        cfg.user = alice.id
        self.assertEqual(set(keys.search([], 0, None, None, {})),
            {alice_key, backup})
        other = users.read([bob.id], ['webauthn_keys'], {})
        self.assertFalse(other[0]['webauthn_keys'])
        for context in [{}, {'user_id': bob.id, '_check_access': False}]:
            with self.assertRaises(AccessError):
                keys.read([bob_key], ['label'], context)
            with self.assertRaises(AccessError):
                keys.write([bob_key], {'label': 'Stolen'}, context)
            with self.assertRaises(AccessError):
                keys.delete([bob_key], context)
        for command in [
                ('write', [bob_key], {'label': 'Stolen'}),
                ('delete', [bob_key]), ('add', [bob_key]),
                ('copy', [bob_key], {}),
                ('create', [{'label': 'Injected'}]),
                ('remove', [alice_key])]:
            with self.assertRaises(AccessError):
                users.set_preferences({'webauthn_keys': [command]}, {})

        # Neither users nor administrators may import or alter key material.
        for actor in [alice.id, admin]:
            cfg.user = actor
            for name, value in {
                    'user': bob.id,
                    'credential_id': 'replacement',
                    'credential_public_key': b'replacement',
                    'sign_count': 0, 'aaguid': 'replacement',
                    'created_at': datetime.datetime.now(),
                    'last_used_at': None,
                    }.items():
                with self.subTest(actor=actor, field=name):
                    with self.assertRaises(AccessError):
                        keys.write([alice_key], {name: value}, {})
                    with self.assertRaises(AccessError):
                        users.set_preferences({'webauthn_keys': [
                            ('write', [alice_key], {name: value})]}, {})
            with self.assertRaises(AccessError):
                keys.create([{'label': 'Injected'}], {})
            with self.assertRaises(AccessError):
                keys.copy([alice_key], {}, {})
            with self.assertRaises(TypeError):
                challenges.search([], 0, None, None, {})
            with self.assertRaises(TypeError):
                challenges.create([{}], {})

        self.assertEqual(set(keys.search([], 0, None, None, {})),
            {alice_key, backup, bob_key})
        # Administrators can rename from the actual user's One2Many form.
        users.write([bob.id], {'webauthn_keys': [
            ('write', [bob_key], {'label': 'Work phone'})]}, {})
        self.assertEqual(Credential(bob_key).label, 'Work phone')
        copied_user, = users.copy([bob.id], {}, {})
        self.assertFalse(users.read(
            [copied_user], ['webauthn_keys'], {})[0]['webauthn_keys'])
        with self.assertRaises(AccessError):
            users.write([bob.id], {'webauthn_keys': [
                ('create', [{'label': 'Injected'}])]}, {})
        with self.assertRaises(AccessError):
            users.set_preferences({'webauthn_keys': [
                ('delete', [bob_key])]}, {})

        # An active user record must not choose who receives a registration.
        wizard = cfg.get_proxy('res.user.webauthn.register', type='wizard')
        context = {'active_model': 'res.user', 'active_id': bob.id,
            'active_ids': [bob.id]}
        session, start, _ = wizard.create(context)
        result = wizard.execute(session, {}, start, context)
        url = result['actions'][0][0]['url']
        mobile_url = url.split('#', 1)[0]
        with Transaction().start(cfg.database_name, 0):
            operation = common.get_operation(
                mobile_url.rsplit('/', 1)[1], channel='mobile')
            self.assertEqual(operation.user.id, admin)
            self.assertEqual(operation.flow, 'preferences')
            self.assertTrue(pool.get('res.user.webauthn.register',
                type='wizard').__rpc__['execute'].fresh_session)
        wizard.delete(session, context)

        cfg.user = alice.id
        # A batch deleting every key must also request last-key confirmation.
        with self.assertRaises(UserWarning):
            keys.delete([alice_key, backup], {})
        users.set_preferences({'webauthn_keys': [
            ('delete', [backup])]}, {})
        with self.assertRaises(UserWarning) as warning:
            users.set_preferences({'webauthn_keys': [
                ('delete', [alice_key])]}, {})
        self.assertEqual(keys.search([], 0, None, None, {}), [alice_key])
        cfg.get_proxy('res.user.warning').skip(warning.exception.name, False, {})
        users.set_preferences({'webauthn_keys': [
            ('delete', [alice_key])]}, {})
        self.assertFalse(keys.search([], 0, None, None, {}))
        cfg.user = bob.id
        self.assertEqual(keys.search([], 0, None, None, {}), [bob_key])
        self.assertEqual(Credential(bob_key).label, 'Work phone')
