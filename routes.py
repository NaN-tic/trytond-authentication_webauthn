# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from html import escape
import json
import re
from io import BytesIO
from pathlib import Path

from trytond.i18n import gettext
from trytond.protocols.wrappers import (
    HTTPStatus, Response, abort, with_pool, with_transaction)
from trytond.transaction import Transaction
from trytond.wsgi import app
import qrcode
from qrcode.image.svg import SvgImage
from webauthn.helpers.exceptions import WebAuthnException

from . import common


def _json(data, status=HTTPStatus.OK):
    response = Response(json.dumps(data, separators=(',', ':')), status=status,
        content_type='application/json')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


def _token(request, name):
    view_args = getattr(request, 'view_args', None) or {}
    value = view_args.get(name) or request.args.get(name)
    if not value or len(value) > 256:
        abort(HTTPStatus.NOT_FOUND)
    return value


def _operation(token, channel, pending=False):
    operation = common.get_operation(token, channel=channel, pending=pending)
    if not operation:
        abort(HTTPStatus.NOT_FOUND)
    return operation


def _options(pool, operation):
    Credential = pool.get('res.user.webauthn.credential')
    credentials = Credential.search([('user', '=', operation.user.id)])
    if operation.purpose == 'registration':
        return common.registration_options(
            operation.user, operation.challenge, credentials)
    return common.authentication_options(operation.challenge, credentials)


def _qr_svg(url):
    output = BytesIO()
    qr = qrcode.QRCode(
        image_factory=SvgImage, error_correction=qrcode.ERROR_CORRECT_M,
        box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    qr.make_image().save(output)
    return output.getvalue()


_MOBILE_MESSAGES = {
    'add_key': ('msg_mobile_add_key', 'Add security key'),
    'approve_access': ('msg_mobile_approve_access', 'Approve access'),
    'initial': ('msg_mobile_initial', 'Tap confirm to continue.'),
    'initiator': ('msg_mobile_initiator', 'Request initiated from'),
    'browser': ('msg_mobile_browser', 'Browser (reported by the device)'),
    'os': ('msg_mobile_os', 'Operating system (reported by the device)'),
    'technical_details': ('msg_mobile_technical_details', 'Technical details'),
    'ip_address': ('msg_mobile_ip_address', 'IP address'),
    'requested_at': ('msg_mobile_requested_at', 'Requested at'),
    'unknown': ('msg_mobile_unknown', 'Not available'),
    'check_request': (
        'msg_mobile_check_request',
        'Only confirm if you initiated this request on the device shown above. '
        'Otherwise, cancel.'),
    'confirm': ('msg_mobile_confirm', 'Confirm with this phone'),
    'cancel': ('msg_mobile_cancel', 'Cancel'),
    'waiting': (
        'msg_mobile_waiting',
        'Waiting for biometric, PIN or phone unlock…'),
    'unavailable': ('msg_mobile_unavailable', 'Operation unavailable.'),
    'rejected': ('msg_mobile_rejected', 'Verification was rejected.'),
    'approved': (
        'msg_mobile_approved',
        'Operation approved. You can return to the computer.'),
    'verification_cancelled': (
        'msg_mobile_verification_cancelled',
        'Verification was cancelled.'),
    'cancelled': ('msg_mobile_cancelled', 'Operation cancelled.'),
    'cancel_failed': (
        'msg_mobile_cancel_failed',
        'The operation could not be cancelled.'),
    'unsupported': (
        'msg_mobile_unsupported',
        'This browser cannot use passkeys.'),
    }


def _mobile_texts(operation):
    language = getattr(operation.user, 'language', None)
    language_code = getattr(language, 'code', None)
    if not language_code:
        language_code = Transaction().language or 'en'
    with Transaction().set_context(language=language_code):
        texts = {}
        for name, (message_id, source) in _MOBILE_MESSAGES.items():
            message = gettext(
                f'authentication_webauthn.{message_id}')
            texts[name] = source if message == (
                f'authentication_webauthn.{message_id}') else message
    texts['title'] = texts[
        'add_key' if operation.purpose == 'registration'
        else 'approve_access']
    texts['language'] = language_code
    return texts


def _browser_details(user_agent):
    # Check specific browsers before the compatibility tokens they include.
    browser = None
    for name, pattern in [
            ('Edge', r'\b(?:Edg|EdgA|EdgiOS|Edge)/(\d+)'),
            ('Opera', r'\b(?:OPR|OPT)/(\d+)'),
            ('Samsung Internet', r'\bSamsungBrowser/(\d+)'),
            ('Firefox', r'\b(?:Firefox|FxiOS)/(\d+)'),
            ('Chromium', r'\bChromium/(\d+)'),
            ('Chrome', r'\b(?:Chrome|CriOS)/(\d+)'),
            ('Safari', r'\bVersion/(\d+).*\bSafari/'),
            ]:
        if match := re.search(pattern, user_agent):
            browser = f'{name} {match[1]}'
            break
    # OS versions are often frozen or reduced (Windows 11 reports NT 10.0).
    operating_system = None
    for name, pattern in [
            ('Windows Phone', r'Windows Phone'),
            ('iOS / iPadOS', r'iPhone|iPad|iPod'),
            ('Android', r'Android'),
            ('ChromeOS', r'CrOS'),
            ('Windows', r'Windows'),
            ('macOS', r'Macintosh|Mac OS X'),
            ('Linux', r'Linux'),
            ]:
        if re.search(pattern, user_agent):
            operating_system = name
            break
    return browser, operating_system


def _mobile_page(operation, token):
    texts = _mobile_texts(operation)
    user_agent = operation.initiator_user_agent or ''
    browser, operating_system = _browser_details(user_agent)
    registration = operation.purpose == 'registration'
    action = 'create' if registration else 'get'
    template_dir = Path(__file__).with_name('www')
    template = (template_dir / 'webauthn-qr.html').read_text(encoding='utf-8')
    css = (template_dir / 'webauthn-qr.css').read_text(encoding='utf-8')
    javascript = (template_dir / 'webauthn-qr.js').read_text(encoding='utf-8')
    javascript = (javascript
        .replace('__TOKEN__', json.dumps(token))
        .replace('__ACTION__', json.dumps(action))
        .replace('__TEXT_WAITING__', json.dumps(texts['waiting']))
        .replace('__TEXT_UNAVAILABLE__', json.dumps(texts['unavailable']))
        .replace('__TEXT_REJECTED__', json.dumps(texts['rejected']))
        .replace('__TEXT_APPROVED__', json.dumps(texts['approved']))
        .replace('__TEXT_VERIFICATION_CANCELLED__',
            json.dumps(texts['verification_cancelled']))
        .replace('__TEXT_CANCELLED__', json.dumps(texts['cancelled']))
        .replace('__TEXT_CANCEL_FAILED__',
            json.dumps(texts['cancel_failed']))
        .replace('__TEXT_UNSUPPORTED__', json.dumps(texts['unsupported'])))
    values = {
        '__LANG__': escape(texts['language']),
        '__TITLE__': escape(texts['title']),
        '__USER__': escape(operation.user.name or operation.user.login),
        '__TEXT_INITIAL__': escape(texts['initial']),
        '__TEXT_CONFIRM__': escape(texts['confirm']),
        '__TEXT_CANCEL__': escape(texts['cancel']),
        '__TEXT_INITIATOR__': escape(texts['initiator']),
        '__TEXT_BROWSER__': escape(texts['browser']),
        '__TEXT_OS__': escape(texts['os']),
        '__TEXT_TECHNICAL_DETAILS__': escape(texts['technical_details']),
        '__TEXT_IP_ADDRESS__': escape(texts['ip_address']),
        '__TEXT_REQUESTED_AT__': escape(texts['requested_at']),
        '__REQUESTED_AT_ISO__': operation.created_at.isoformat() + 'Z',
        '__REQUESTED_AT_UTC__': operation.created_at.strftime(
            '%Y-%m-%d %H:%M:%S UTC'),
        '__TEXT_CHECK_REQUEST__': escape(texts['check_request']),
        '__INITIATOR_IP__': escape(operation.initiator or texts['unknown']),
        '__INITIATOR_BROWSER__': escape(browser or texts['unknown']),
        '__INITIATOR_OS__': escape(operating_system or texts['unknown']),
        '__INITIATOR_USER_AGENT__': escape(user_agent or texts['unknown']),
        '__CSS__': css,
        '__JS__': javascript,
        }
    # Substitute once so user-controlled text cannot expand template markers.
    return re.sub(r'__[A-Z_]+__', lambda match: values[match[0]], template)


@app.route('/<database_name>/authentication/webauthn/qr/<mobile_token>', methods={'GET'})
@with_pool
@with_transaction(readonly=False)
def mobile_page(request, pool, mobile_token):
    token = _token(request, 'mobile_token')
    operation = _operation(token, 'mobile', True)
    response = Response(_mobile_page(operation, token), content_type='text/html')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/<database_name>/authentication/webauthn/qr-code/<mobile_token>.svg', methods={'GET'})
@with_pool
@with_transaction(readonly=False)
def qr_code(request, pool, mobile_token):
    token = _token(request, 'mobile_token')
    _operation(token, 'mobile', True)
    database = (getattr(request, 'view_args', None) or {})['database_name']
    url = f'{common.base_url(request.context)}/{database}/authentication/webauthn/qr/{token}'
    return Response(_qr_svg(url), content_type='image/svg+xml')


@app.route('/<database_name>/authentication/webauthn/qr/<mobile_token>/options', methods={'GET'})
@with_pool
@with_transaction(readonly=False)
def mobile_options(request, pool, mobile_token):
    operation = _operation(_token(request, 'mobile_token'), 'mobile', True)
    try:
        options = _options(pool, operation)
    except WebAuthnException:
        abort(HTTPStatus.BAD_REQUEST)
    return _json({'options': options, 'rp_id': common.rp_id(), 'purpose': operation.purpose})


@app.route('/<database_name>/authentication/webauthn/qr/<mobile_token>/complete', methods={'POST'})
@with_pool
@with_transaction(readonly=False)
def mobile_complete(request, pool, mobile_token):
    token = _token(request, 'mobile_token')
    operation = _operation(token, 'mobile', True)
    credential = (request.get_json(silent=True) or {}).get('credential')
    if not credential:
        return _json({
            'error': gettext('authentication_webauthn.msg_missing_credential')
            }, HTTPStatus.BAD_REQUEST)
    User = pool.get('res.user')
    try:
        if operation.purpose == 'registration':
            User._store_registration(operation.user.id, operation, credential)
        else:
            User._verify_authentication(operation.user.id, operation, credential)
    except WebAuthnException:
        User._record_failed_attempt(operation)
        return _json({'status': 'rejected'}, HTTPStatus.BAD_REQUEST)
    if not common.complete_operation(operation):
        # Verification may have stored a credential or updated its counter
        # before the challenge expired or became unavailable. The route commits
        # even error responses, so undo those changes before returning HTTP 410.
        Transaction().rollback()
        return _json({'status': 'expired'}, HTTPStatus.GONE)
    return _json({'status': 'approved'})


@app.route('/<database_name>/authentication/webauthn/qr/<mobile_token>/cancel', methods={'POST'})
@with_pool
@with_transaction(readonly=False)
def mobile_cancel(request, pool, mobile_token):
    operation = _operation(_token(request, 'mobile_token'), 'mobile', True)
    reason = (request.get_json(silent=True) or {}).get('reason', 'cancelled')
    if reason not in {'cancelled', 'rejected'}:
        reason = 'cancelled'
    pool.get('res.user.webauthn.challenge').write([operation], {
            'status': 'cancelled', 'status_reason': reason})
    return _json({'status': 'cancelled'})


@app.route('/<database_name>/authentication/webauthn/desktop/status', methods={'GET'})
@with_pool
@with_transaction(readonly=False)
def desktop_status(request, pool):
    operation = _operation(_token(request, 'desktop_token'), 'desktop')
    return _json({'status': operation.status, 'reason': operation.status_reason,
            'purpose': operation.purpose, 'flow': operation.flow,
            'expires_at': operation.expires_at.isoformat()})


@app.route('/<database_name>/authentication/webauthn/desktop/options', methods={'GET'})
@with_pool
@with_transaction(readonly=False)
def desktop_options(request, pool):
    operation = _operation(_token(request, 'desktop_token'), 'desktop', True)
    try:
        options = _options(pool, operation)
    except WebAuthnException:
        abort(HTTPStatus.BAD_REQUEST)
    return _json({'options': options, 'purpose': operation.purpose})


@app.route('/<database_name>/authentication/webauthn/desktop/complete', methods={'POST'})
@with_pool
@with_transaction(readonly=False)
def desktop_complete(request, pool):
    payload = request.get_json(silent=True) or {}
    operation = _operation(payload.get('desktop_token', ''), 'desktop', True)
    credential = payload.get('credential')
    if not credential:
        return _json({
            'error': gettext('authentication_webauthn.msg_missing_credential')
            }, HTTPStatus.BAD_REQUEST)
    User = pool.get('res.user')
    try:
        if operation.purpose == 'registration':
            User._store_registration(operation.user.id, operation, credential)
        else:
            User._verify_authentication(operation.user.id, operation, credential)
    except WebAuthnException:
        User._record_failed_attempt(operation)
        return _json({'status': 'rejected'}, HTTPStatus.BAD_REQUEST)
    if not common.complete_operation(operation):
        # Verification may have stored a credential or updated its counter
        # before the challenge expired or became unavailable. The route commits
        # even error responses, so undo those changes before returning HTTP 410.
        Transaction().rollback()
        return _json({'status': 'expired'}, HTTPStatus.GONE)
    return _json({'status': 'approved'})


@app.route('/<database_name>/authentication/webauthn/desktop/regenerate', methods={'POST'})
@with_pool
@with_transaction(readonly=False)
def desktop_regenerate(request, pool):
    payload = request.get_json(silent=True) or {}
    operation = _operation(payload.get('desktop_token', ''), 'desktop', True)
    pool.get('res.user.webauthn.challenge').write([operation], {
            'status': 'cancelled', 'status_reason': 'regenerated'})
    return _json(common.create_operation(operation.user, operation.purpose,
            flow=operation.flow, initiator={
                'remote_addr': operation.initiator,
                'user_agent': operation.initiator_user_agent,
                }))


@app.route('/<database_name>/authentication/webauthn/desktop/cancel', methods={'POST'})
@with_pool
@with_transaction(readonly=False)
def desktop_cancel(request, pool):
    payload = request.get_json(silent=True) or {}
    token = payload.get('desktop_token') or request.args.get('desktop_token', '')
    operation = _operation(token, 'desktop', True)
    pool.get('res.user.webauthn.challenge').write([operation], {
            'status': 'cancelled', 'status_reason': 'cancelled'})
    return _json({'status': 'cancelled'})
