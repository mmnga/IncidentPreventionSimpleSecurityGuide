"""SYNTHETIC WSGI application factory. No server, DB or account starts on import."""
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import parse_qs

from .security import (Rejected, allowed_keys, authenticate, audit_event,
                       bounded_int, password_matches, reserve_budget)

WEB_ORIGIN = 'https://web.atlas.invalid'


def initialize_database(db):
    db.executescript(Path(__file__).with_name('schema.sql').read_text())


def dispatch(db, method, path, data, query, token, sink):
    if path == '/health' and method == 'GET':
        return 200, {'status': 'synthetic'}
    if path == '/v1/session' and method == 'POST':
        allowed_keys(data, {'email', 'password'})
        email = str(data.get('email', '')).strip().casefold()[:254]
        reserve_budget(db, email, 'login', maximum=10)
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        # A provisioning flow must provide this dummy hash; it is never a real credential.
        dummy = '00' * 16 + ':' + '00' * 64
        valid = password_matches(data.get('password', ''), user['password_hash'] if user else dummy)
        if not user or not valid or not user['active']:
            raise Rejected(401, 'authentication_failed')
        # Enrollment alone is not MFA verification. A real IdP/step-up adapter is
        # deliberately absent, so this password-only entry point rejects admins.
        if user['role'] == 'admin':
            raise Rejected(403, 'admin_identity_provider_required')
        raw = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
            (hashlib.sha256(raw.encode()).hexdigest(), user['id'], user['auth_version'], int(time.time()) + 1800))
        return 200, {'access_token': raw, 'expires_in': 1800}
    actor = authenticate(db, token)
    if path == '/v1/session' and method == 'DELETE':
        db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))
        audit_event(sink, actor, 'logout', actor['id'])
        return 200, {'revoked': True}
    if path == '/v1/notes' and method == 'GET':
        limit = bounded_int(query.get('limit', ['20'])[0])
        reserve_budget(db, actor['tenant_id'] + ':' + actor['id'], 'read', cost=limit)
        rows = db.execute('''SELECT id,title,body FROM notes WHERE tenant_id=? AND owner_id=?
            ORDER BY created_at DESC LIMIT ?''', (actor['tenant_id'], actor['id'], limit)).fetchall()
        audit_event(sink, actor, 'notes.read', 'notes', count=len(rows))
        return 200, {'items': [dict(r) for r in rows]}
    if path == '/v1/notes' and method == 'POST':
        allowed_keys(data, {'title', 'body'})
        title, body = data.get('title'), data.get('body')
        if not isinstance(title, str) or not 1 <= len(title) <= 120 or not isinstance(body, str) or len(body) > 4000:
            raise Rejected(400, 'invalid_note')
        nid = secrets.token_hex(16)
        db.execute('INSERT INTO notes VALUES (?,?,?,?,?,?)',
            (nid, actor['tenant_id'], actor['id'], title, body, int(time.time())))
        audit_event(sink, actor, 'notes.create', nid)
        return 201, {'id': nid}
    if path.startswith('/v1/notes/') and method == 'DELETE':
        nid = path.removeprefix('/v1/notes/')
        changed = db.execute('DELETE FROM notes WHERE id=? AND tenant_id=? AND owner_id=?',
                             (nid, actor['tenant_id'], actor['id'])).rowcount
        if not changed:
            raise Rejected(404, 'not_found')
        audit_event(sink, actor, 'notes.delete', nid)
        return 200, {'deleted': True}
    if path == '/v1/exports' and method == 'POST':
        allowed_keys(data, set())
        reserve_budget(db, actor['tenant_id'] + ':' + actor['id'], 'export', maximum=3)
        jid = secrets.token_hex(16)
        db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',
            (jid, actor['tenant_id'], actor['id'], actor['auth_version'], 'pending', None, int(time.time()) + 600))
        audit_event(sink, actor, 'export.request', jid)
        return 202, {'id': jid}
    if path.startswith('/v1/exports/') and method == 'GET':
        row = db.execute('SELECT * FROM jobs WHERE id=? AND tenant_id=? AND actor_id=?',
            (path.removeprefix('/v1/exports/'), actor['tenant_id'], actor['id'])).fetchone()
        if not row or row['expires_at'] <= int(time.time()) or row['auth_version'] != actor['auth_version']:
            raise Rejected(404, 'not_found')
        return 200, {'status': row['status'], 'items': json.loads(row['result_json'] or '[]')}
    if path == '/v1/inquiries' and method == 'POST':
        allowed_keys(data, {'body'})
        if not isinstance(data.get('body'), str) or not 1 <= len(data['body']) <= 4000:
            raise Rejected(400, 'invalid_inquiry')
        reserve_budget(db, actor['id'], 'receipt', maximum=3)
        receipt = secrets.token_hex(16)
        db.execute('INSERT INTO inquiries VALUES (?,?,?,?,?)',
            (receipt, actor['tenant_id'], actor['id'], data['body'], int(time.time())))
        db.execute('INSERT INTO outbox(event_id,kind,recipient_id,receipt_id) VALUES (?,?,?,?)',
            (secrets.token_hex(16), 'receipt.v1', actor['id'], receipt))
        audit_event(sink, actor, 'inquiry.create', receipt)
        return 202, {'receipt_id': receipt}
    if path == '/v1/admin/disable' and method == 'POST':
        allowed_keys(data, {'user_id'})
        if actor['role'] != 'admin' or not actor['mfa_enrolled']:
            raise Rejected()
        changed = db.execute('UPDATE users SET active=0,auth_version=auth_version+1 WHERE id=? AND tenant_id=?',
                             (data.get('user_id'), actor['tenant_id'])).rowcount
        if not changed:
            raise Rejected(404, 'not_found')
        audit_event(sink, actor, 'account.disable', data['user_id'])
        return 200, {'disabled': True}
    raise Rejected(404, 'not_found')


def create_app(database_path, audit_sink):
    def application(environ, start_response):
        db = None
        headers = [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'),
                   ('X-Content-Type-Options', 'nosniff'), ('Vary', 'Origin')]
        try:
            if environ.get('HTTP_HOST') not in {'api.atlas.invalid'} or environ.get('wsgi.url_scheme') != 'https':
                raise Rejected(400, 'invalid_origin')
            origin = environ.get('HTTP_ORIGIN')
            if origin and origin != WEB_ORIGIN:
                raise Rejected()
            if origin:
                headers.append(('Access-Control-Allow-Origin', WEB_ORIGIN))
            method = environ.get('REQUEST_METHOD', 'GET')
            if method == 'OPTIONS':
                headers += [('Access-Control-Allow-Headers', 'Authorization, Content-Type'),
                            ('Access-Control-Allow-Methods', 'GET, POST, DELETE')]
                status, value = 204, None
            else:
                length = bounded_int(environ.get('CONTENT_LENGTH') or '1', maximum=16384)
                raw = environ['wsgi.input'].read(length) if environ.get('CONTENT_LENGTH') else b'{}'
                if method == 'POST' and environ.get('CONTENT_TYPE') != 'application/json':
                    raise Rejected(415, 'json_required')
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise Rejected(400, 'object_required')
                auth = environ.get('HTTP_AUTHORIZATION', '')
                token = auth[7:] if auth.startswith('Bearer ') else ''
                db = sqlite3.connect(database_path, timeout=3)
                db.row_factory = sqlite3.Row
                db.execute('BEGIN IMMEDIATE')
                status, value = dispatch(db, method, environ.get('PATH_INFO', ''), data,
                    parse_qs(environ.get('QUERY_STRING', '')), token, audit_sink)
                db.commit()
        except Rejected as error:
            # Keep failed-login budget reservations; security state updates precede rejection.
            if db:
                db.commit()
            status, value = error.status, {'error': error.code}
        except (ValueError, KeyError, sqlite3.Error):
            if db:
                db.rollback()
            status, value = 400, {'error': 'request_failed'}
        finally:
            if db:
                db.close()
        start_response(str(status) + ' Response', headers)
        return [b'' if value is None else json.dumps(value).encode()]
    return application
