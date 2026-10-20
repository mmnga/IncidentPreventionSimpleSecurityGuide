"""SYNTHETIC reference boundaries; imported only by an explicitly started app."""
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlsplit


class Rejected(Exception):
    def __init__(self, status=403, code='request_rejected'):
        self.status, self.code = status, code


def password_hash(password, salt=None):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise Rejected(400, 'invalid_password')
    salt = salt or secrets.token_hex(16)
    derived = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return salt + ':' + derived.hex()


def password_matches(password, encoded):
    try:
        salt, _ = encoded.split(':', 1)
        return hmac.compare_digest(password_hash(password, salt), encoded)
    except (ValueError, TypeError):
        return False


def authenticate(db, token):
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        raise Rejected(401, 'authentication_required')
    row = db.execute('''SELECT u.*, s.auth_version AS session_version, s.expires_at
        FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?''',
        (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not row or not row['active'] or row['expires_at'] <= int(time.time()):
        raise Rejected(401, 'authentication_required')
    if row['auth_version'] != row['session_version']:
        raise Rejected(401, 'authentication_required')
    return dict(row)


def reserve_budget(db, principal, purpose, cost=1, maximum=100, seconds=3600):
    """Call inside BEGIN IMMEDIATE: one atomic budget shared by API and workers."""
    if type(cost) is not int or cost < 1 or cost > maximum:
        raise Rejected(429, 'budget_exceeded')
    window = int(time.time()) // seconds
    db.execute('INSERT OR IGNORE INTO budgets VALUES (?,?,?,0)', (principal, purpose, window))
    used = db.execute('SELECT used FROM budgets WHERE principal=? AND purpose=? AND window=?',
                      (principal, purpose, window)).fetchone()[0]
    if used + cost > maximum:
        raise Rejected(429, 'budget_exceeded')
    db.execute('UPDATE budgets SET used=used+? WHERE principal=? AND purpose=? AND window=?',
               (cost, principal, purpose, window))


def bounded_int(value, maximum=100):
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdigit():
        raise Rejected(400, 'invalid_limit')
    number = int(value)
    if not 1 <= number <= maximum:
        raise Rejected(400, 'invalid_limit')
    return number


def allowed_keys(value, keys):
    if not isinstance(value, dict) or set(value) - set(keys):
        raise Rejected(400, 'unexpected_fields')
    return value


def safe_external_url(value):
    # Server-owned list: never fetch an arbitrary client-selected URL.
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in {'hooks.partner.invalid'}
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.fragment or parsed.path != '/events'):
        raise Rejected(400, 'invalid_destination')
    return value


def audit_event(sink, actor, action, target, count=1, outcome='ok'):
    # No passwords, access tokens, inquiry bodies or response payloads.
    sink(json.dumps({'actor': actor['id'], 'tenant': actor['tenant_id'],
        'action': action, 'target': target, 'count': count, 'outcome': outcome,
        'at': int(time.time()), 'correlation': secrets.token_hex(8)}, separators=(',', ':')))
