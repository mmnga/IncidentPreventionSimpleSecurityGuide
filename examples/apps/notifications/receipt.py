"""SYNTHETIC mail generator only. No SMTP client, DNS or sending credentials."""
from email.message import EmailMessage
import re


def make_receipt(event, lookup_verified_recipient):
    if set(event) != {'event_id', 'kind', 'recipient_id', 'receipt_id'} or event['kind'] != 'receipt.v1':
        raise ValueError('Unsupported notification event')
    for key in ('event_id', 'receipt_id'):
        if not isinstance(event[key], str) or not re.fullmatch('[a-f0-9]{32}', event[key]):
            raise ValueError('Invalid server-generated identifier')
    # The notifier DB role can read verified recipient metadata and outbox, not inquiries.body.
    recipient = lookup_verified_recipient(event['recipient_id'])
    if not recipient or '\r' in recipient or '\n' in recipient:
        raise ValueError('Recipient not verified')
    message = EmailMessage()
    message['From'] = 'support@notify.atlas.invalid'
    message['To'] = recipient
    message['Subject'] = 'お問い合わせを受け付けました'
    message['Auto-Submitted'] = 'auto-generated'
    message.set_content('受付が完了しました。\n受付番号: ' + event['receipt_id'] +
        '\n内容は https://web.atlas.invalid/support へログインしてご確認ください。')
    return message


def claim_event(db, event_id):
    # A delivery adapter needs its own idempotency key for crash-after-send reconciliation.
    return db.execute("UPDATE outbox SET state='claimed' WHERE event_id=? AND state='pending'",
                      (event_id,)).rowcount == 1
