# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.model import ModelSQL, Unique, fields
from webauthn.helpers import base64url_to_bytes


class WebAuthnCredential(ModelSQL):
    __name__ = 'res.user.webauthn.credential'

    user = fields.Many2One(
        'res.user', 'User', required=True, ondelete='CASCADE')
    credential_id = fields.Char('Credential ID', required=True, readonly=True,
        strip=False)
    credential_public_key = fields.Binary(
        'Credential Public Key', required=True, readonly=True)
    sign_count = fields.Integer('Sign Count', required=True, readonly=True)
    aaguid = fields.Char('AAGUID', readonly=True, strip=False)
    label = fields.Char('Label', required=True)
    created_at = fields.DateTime('Created At', required=True, readonly=True)
    last_used_at = fields.DateTime('Last Used At', readonly=True)

    @property
    def credential_id_bytes(self):
        return base64url_to_bytes(self.credential_id)

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_constraints += [
            ('credential_id_unique', Unique(table, table.credential_id),
                'Credential ID must be unique.'),
            ]


class WebAuthnChallenge(ModelSQL):
    __name__ = 'res.user.webauthn.challenge'

    user = fields.Many2One(
        'res.user', 'User', required=True, ondelete='CASCADE')
    purpose = fields.Selection([
            ('registration', 'Registration'),
            ('authentication', 'Authentication'),
            ], 'Purpose', required=True, readonly=True)
    flow = fields.Selection([
            ('login', 'Login'),
            ('preferences', 'Preferences'),
            ], 'Flow', required=True, readonly=True)
    token = fields.Char('Legacy Token', required=True, readonly=True,
        strip=False)
    mobile_token_hash = fields.Char(
        'Mobile Token Hash', required=True, readonly=True, strip=False)
    desktop_token_hash = fields.Char(
        'Desktop Token Hash', required=True, readonly=True, strip=False)
    challenge = fields.Binary('Challenge', required=True, readonly=True)
    status = fields.Selection([
            ('pending', 'Pending'),
            ('completed', 'Completed'),
            ('cancelled', 'Cancelled'),
            ('expired', 'Expired'),
            ], 'Status', required=True, readonly=True)
    status_reason = fields.Char('Status Reason', readonly=True)
    created_at = fields.DateTime('Created At', required=True, readonly=True)
    expires_at = fields.DateTime('Expires At', required=True, readonly=True)
    completed_at = fields.DateTime('Completed At', readonly=True)
    attempts = fields.Integer('Attempts', required=True, readonly=True)
    consumed = fields.Boolean('Consumed', readonly=True)
    initiator = fields.Char('Initiating IP Address', readonly=True)
    initiator_user_agent = fields.Char(
        'Initiating User Agent', size=512, readonly=True)

    @staticmethod
    def default_attempts():
        return 0

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_constraints += [
            ('mobile_token_unique', Unique(table, table.mobile_token_hash),
                'Mobile token hash must be unique.'),
            ('desktop_token_unique', Unique(table, table.desktop_token_hash),
                'Desktop token hash must be unique.'),
            ]
