# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import hashlib
import json
from secrets import token_bytes, token_urlsafe
from urllib.parse import quote, urlsplit

from sql.conditionals import Case

import trytond.config as config
from trytond.pool import Pool
from trytond.transaction import Transaction
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .wsgi import user_agent


def rp_id():
    parsed = urlsplit(base_url())
    return parsed.hostname or 'localhost'


def origin():
    parsed = urlsplit(base_url())
    if parsed.scheme and parsed.netloc:
        return f'{parsed.scheme}://{parsed.netloc}'
    return base_url()


def timeout():
    return config.getint(
        'authentication_webauthn', 'timeout', default=60 * 1000)


def challenge_ttl():
    return config.getint(
        'authentication_webauthn', 'challenge_ttl', default=2 * 60)


def max_attempts():
    return config.getint(
        'authentication_webauthn', 'max_attempts', default=5)


def base_url(request=None):
    configured = config.get('web', 'base_url', default='').strip()
    if configured:
        return configured.rstrip('/')
    if request and request.get('http_host'):
        return f"{request.get('scheme', 'https')}://{request['http_host']}".rstrip('/')
    return 'http://localhost:8024'


def verification_requirement():
    values = {
        'required': UserVerificationRequirement.REQUIRED,
        'preferred': UserVerificationRequirement.PREFERRED,
        'discouraged': UserVerificationRequirement.DISCOURAGED,
        }
    value = config.get(
        'authentication_webauthn', 'user_verification', default='required')
    try:
        return values[value.lower()]
    except KeyError as exception:
        raise ValueError(
            'Invalid authentication_webauthn user_verification') from exception


def user_handle(user_id):
    value = f'{rp_id()}:{user_id}'.encode('utf-8')
    return hashlib.sha256(value).digest()


def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_operation(user, purpose, flow='login', *, initiator=None):
    Operation = Pool().get('res.user.webauthn.challenge')
    challenge = token_bytes(32)
    mobile_token = token_urlsafe(32)
    desktop_token = token_urlsafe(32)
    now = datetime.datetime.now()
    request = Transaction().context.get('_request') or {}
    if initiator is None:
        initiator = {
            **request,
            'user_agent': user_agent.get() or request.get('user_agent'),
            }
    Operation.create([{
            'user': user.id,
            'purpose': purpose,
            'flow': flow,
            'token': hash_token(desktop_token),
            'mobile_token_hash': hash_token(mobile_token),
            'desktop_token_hash': hash_token(desktop_token),
            'challenge': challenge,
            'status': 'pending',
            'created_at': now,
            'expires_at': now + datetime.timedelta(seconds=challenge_ttl()),
            'attempts': 0,
            'consumed': False,
            'initiator': initiator.get('remote_addr'),
            'initiator_user_agent': (initiator.get('user_agent') or '')[:512],
            }])
    database = quote(Transaction().database.name, safe='')
    encoded_mobile = quote(mobile_token, safe='')
    base = base_url(request)
    return {
        'desktop_token': desktop_token,
        'mobile_token': mobile_token,
        'mobile_url': (
            f'{base}/{database}/authentication/webauthn/qr/{encoded_mobile}'),
        'qr_url': (
            f'{base}/{database}/authentication/webauthn/qr-code/'
            f'{encoded_mobile}.svg'),
        'purpose': purpose,
        'flow': flow,
        'user': user.name or user.login,
        'expires_at': (
            now + datetime.timedelta(seconds=challenge_ttl())).isoformat(),
        }


def get_operation(token, *, channel, pending=False, purpose=None):
    Operation = Pool().get('res.user.webauthn.challenge')
    token_field = {
        'mobile': 'mobile_token_hash',
        'desktop': 'desktop_token_hash',
        }[channel]
    domain = [
        (token_field, '=', hash_token(token)),
        ('consumed', '=', False),
        ]
    if purpose:
        domain.append(('purpose', '=', purpose))
    operations = Operation.search(domain, limit=1)
    if not operations:
        return
    operation = operations[0]
    if (operation.status in {'pending', 'completed'}
            and operation.expires_at <= datetime.datetime.now()):
        Operation.write([operation], {'status': 'expired'})
    if pending and operation.status != 'pending':
        return
    return operation


def complete_operation(operation, *, consumed=False):
    Operation = Pool().get('res.user.webauthn.challenge')
    now = datetime.datetime.now()
    table = Operation.__table__()
    values = [table.status, table.completed_at]
    updates = ['completed', now]
    if consumed:
        values.append(table.consumed)
        updates.append(True)
    where = (
        (table.id == operation.id)
        & (table.status == 'pending')
        & (table.consumed == False)
        & (table.expires_at > now)
        )
    with Transaction().connection.cursor() as cursor:
        cursor.execute(*table.update(values, updates, where=where))
        if not cursor.rowcount:
            return False
    values = {'status': 'completed', 'completed_at': now}
    if consumed:
        values['consumed'] = True
    Operation.write([operation], values)
    return True


def consume_operation(operation):
    Operation = Pool().get('res.user.webauthn.challenge')
    now = datetime.datetime.now()
    table = Operation.__table__()
    where = (
        (table.id == operation.id)
        & (table.status == 'completed')
        & (table.consumed == False)
        & (table.expires_at > now)
        )
    with Transaction().connection.cursor() as cursor:
        cursor.execute(*table.update(
            [table.consumed], [True], where=where))
        if not cursor.rowcount:
            return False
    Operation.write([operation], {'consumed': True})
    return True


def record_failed_attempt(operation):
    Operation = Pool().get('res.user.webauthn.challenge')
    now = datetime.datetime.now()
    table = Operation.__table__()
    attempts = table.attempts + 1
    rejected_expression = attempts >= max_attempts()
    where = (
        (table.id == operation.id)
        & (table.status == 'pending')
        & (table.consumed == False)
        & (table.expires_at > now)
        )
    values = [
        table.attempts,
        table.status,
        table.status_reason,
        ]
    updates = [
        attempts,
        Case((rejected_expression, 'cancelled'), else_=table.status),
        Case((rejected_expression, 'rejected'), else_=table.status_reason),
        ]
    with Transaction().connection.cursor() as cursor:
        cursor.execute(*table.update(values, updates, where=where))
        if not cursor.rowcount:
            return False
        # Read back the atomic update while holding the write lock. The record
        # cache may predate another request's increment and must not undo it.
        cursor.execute(*table.select(
            table.attempts, table.status, table.status_reason,
            where=table.id == operation.id))
        attempts, status, status_reason = cursor.fetchone()
    Operation.write([operation], {
        'attempts': attempts,
        'status': status,
        'status_reason': status_reason,
        })
    return True


def create_challenge(user_id, purpose):
    User = Pool().get('res.user')
    descriptor = create_operation(User(user_id), purpose, flow='preferences')
    operation = get_operation(
        descriptor['desktop_token'], channel='desktop', pending=True)
    return descriptor['desktop_token'], operation.challenge


def get_challenge(user_id, token, purpose=None):
    operation = get_operation(
        token, channel='desktop', pending=True, purpose=purpose)
    if operation and operation.user.id == user_id:
        return operation


def registration_options(user, challenge, credentials):
    excluded = [PublicKeyCredentialDescriptor(
            id=credential.credential_id_bytes)
        for credential in credentials]
    options = generate_registration_options(
        rp_id=rp_id(),
        rp_name=config.get(
            'authentication_webauthn', 'rp_name', default='Tryton'),
        user_name=user.login,
        user_id=user_handle(user.id),
        user_display_name=user.name or user.login,
        challenge=challenge,
        timeout=timeout(),
        exclude_credentials=excluded,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=verification_requirement()),
        hints=[
            PublicKeyCredentialHint.HYBRID,
            PublicKeyCredentialHint.CLIENT_DEVICE,
            ],
        )
    return json.loads(options_to_json(options))


def authentication_options(challenge, credentials):
    allowed = [PublicKeyCredentialDescriptor(
            id=credential.credential_id_bytes)
        for credential in credentials]
    options = generate_authentication_options(
        rp_id=rp_id(),
        challenge=challenge,
        timeout=timeout(),
        allow_credentials=allowed,
        user_verification=verification_requirement(),
        )
    result = json.loads(options_to_json(options))
    result['hints'] = ['hybrid', 'client-device']
    return result
