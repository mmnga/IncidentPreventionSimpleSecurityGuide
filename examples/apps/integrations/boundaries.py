"""SYNTHETIC integration gates. All network/IdP verification is injected."""
import hashlib
import hmac
import json
import secrets
import time


def oauth_request(session):
    verifier = secrets.token_urlsafe(32)
    import base64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    session.update(state=secrets.token_urlsafe(24), verifier=verifier, expires_at=int(time.time())+300)
    return {'state': session['state'], 'code_challenge': challenge, 'code_challenge_method': 'S256',
            'redirect_uri': 'https://web.atlas.invalid/oauth/callback', 'scope': 'openid profile'}


def verify_id_token(token, verify_signature):
    # Never replace verify_signature with a decode-only implementation.
    claims = verify_signature(token, algorithms=['RS256'], issuer='https://id.atlas.invalid', audience='atlas')
    if not claims.get('sub') or claims['exp'] <= int(time.time()):
        raise ValueError('Invalid identity')
    return claims


def accept_webhook(db, raw, event_id, timestamp, supplied_signature, key):
    if abs(int(time.time()) - int(timestamp)) > 300 or len(raw) > 65536:
        raise ValueError('Expired or oversized event')
    expected = hmac.new(key, str(timestamp).encode() + b'.' + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied_signature):
        raise ValueError('Invalid signature')
    value = json.loads(raw)
    if set(value) != {'type', 'tenant_id', 'object_id'} or value['type'] != 'note.updated':
        raise ValueError('Unexpected provider response')
    # Must bind tenant_id to the authenticated connector registration before applying.
    db.execute('INSERT INTO webhook_seen VALUES (?,?)', (event_id, int(time.time())))
    return value


def disconnect(db, connector_id, actor, authorized_delete):
    authorized_delete(db, connector_id, actor['tenant_id'])
    # Revoke provider grant, refresh tokens, queued work and callbacks; no auto-reactivation.
