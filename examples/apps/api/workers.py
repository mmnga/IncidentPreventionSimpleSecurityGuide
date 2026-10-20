"""SYNTHETIC export worker: recheck identity/tenant/version before reading."""
import json
import time
from .security import Rejected, audit_event, reserve_budget


def process_export(db, job_id, sink):
    """Own the write transaction so workers share the same atomic API budget."""
    if db.in_transaction:
        raise RuntimeError('Worker requires its own transaction')
    db.execute('BEGIN IMMEDIATE')
    try:
        _process_export(db, job_id, sink)
        db.commit()
    except Exception:
        db.rollback()
        raise


def _process_export(db, job_id, sink):
    job = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
    if not job or job['status'] != 'pending' or job['expires_at'] <= int(time.time()):
        raise Rejected(404, 'job_unavailable')
    actor = db.execute('SELECT * FROM users WHERE id=? AND tenant_id=?',
        (job['actor_id'], job['tenant_id'])).fetchone()
    if not actor or not actor['active'] or actor['auth_version'] != job['auth_version']:
        db.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (job_id,))
        return
    reserve_budget(db, actor['tenant_id'] + ':' + actor['id'], 'read', cost=100)
    rows = db.execute('SELECT id,title,body FROM notes WHERE tenant_id=? AND owner_id=? LIMIT 100',
                      (actor['tenant_id'], actor['id'])).fetchall()
    db.execute("UPDATE jobs SET status='complete', result_json=? WHERE id=? AND status='pending'",
               (json.dumps([dict(r) for r in rows]), job_id))
    audit_event(sink, actor, 'export.complete', job_id, count=len(rows))


def delete_expired(db, now):
    db.execute('DELETE FROM sessions WHERE expires_at<=?', (now,))
    db.execute('DELETE FROM jobs WHERE expires_at<=?', (now,))
    db.execute('DELETE FROM budgets WHERE window<?', (now // 3600 - 24,))
    # Restored backups must run the same retention/tombstone reconciliation before serving.
