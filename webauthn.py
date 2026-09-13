# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.

from trytond.exceptions import UserError, UserWarning
from trytond.i18n import gettext
from trytond.model import ModelSQL, ModelView, Unique, fields
from trytond.model.exceptions import AccessError
from trytond.pool import Pool
from trytond.transaction import Transaction
from webauthn.helpers import base64url_to_bytes


class WebAuthnCredential(ModelSQL, ModelView):
    __name__ = 'res.user.webauthn.credential'
    __string__ = 'Security Key'
    _rec_name = 'label'

    user = fields.Many2One(
        'res.user', 'User', required=True, readonly=True, ondelete='CASCADE')
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
        cls.__rpc__['write'].fresh_session = True
        cls.__rpc__['delete'].fresh_session = True
        table = cls.__table__()
        cls._sql_constraints += [
            ('credential_id_unique', Unique(table, table.credential_id),
                'Credential ID must be unique.'),
            ]

    @classmethod
    def create(cls, vlist):
        # Readonly widgets and configurable ACLs are not an enrollment boundary.
        if Transaction().check_access:
            raise AccessError(gettext(
                'authentication_webauthn.msg_verified_registration_required'))
        return super().create(vlist)

    @classmethod
    def write(cls, records, values, *args):
        actions = iter((records, values) + args)
        updates = []
        for records, values in zip(actions, actions):
            if Transaction().check_access and values.keys() - {'label'}:
                raise AccessError(gettext(
                    'authentication_webauthn.msg_credential_immutable'))
            values = values.copy()
            if 'label' in values:
                label = values['label']
                if not isinstance(label, str) or not label.strip():
                    raise UserError(gettext(
                        'authentication_webauthn.msg_invalid_label'))
                values['label'] = label.strip()
            updates.extend((records, values))
        super().write(*updates)

    @classmethod
    def delete(cls, records):
        if Transaction().check_access:
            pool = Pool()
            pool.get('ir.model.access').check(cls.__name__, 'delete')
            pool.get('ir.rule').check(
                cls.__name__, [r.id for r in records], 'delete')
            # Serialize revocations so concurrent deletions cannot both miss
            # the last credential. Authentication also updates this table.
            cls.lock()
            Warning = pool.get('res.user.warning')
            ids = [r.id for r in records]
            for user in {r.user for r in records}:
                if not cls.search([
                        ('user', '=', user.id), ('id', 'not in', ids)],
                        limit=1):
                    warning = Warning.format('webauthn_last_key', [user])
                    if Warning.check(warning):
                        raise UserWarning(warning, gettext(
                            'authentication_webauthn.msg_revoke_last_key',
                            user=user.rec_name))
        super().delete(records)


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
