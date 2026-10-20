'use strict';
// SYNTHETIC: no analytics, credentials, persisted tokens or external requests by default.
const nodes = Object.fromEntries(['notes', 'title', 'body', 'inquiry', 'receipt', 'result', 'error']
  .map(id => [id, document.getElementById(id)]));
const demo = {
  notes: [{id: 'synthetic-1', title: 'レビューを始める', body: '入力はHTMLとして描画しません。'}],
  async list() { return {items: this.notes}; },
  async add(title, body) { this.notes.push({id: crypto.randomUUID(), title, body}); },
  async contact(body) { if (!body.trim()) throw new Error('本文を入力してください'); return {receipt_id: crypto.randomUUID()}; },
  async export() { return {items: this.notes}; }
};

class Api {
  constructor(token) { this.token = token; }
  async request(path, method = 'GET', data) {
    if (!['/v1/notes', '/v1/inquiries', '/v1/exports'].includes(path)) throw new Error('許可されないAPI');
    const response = await fetch('https://api.atlas.invalid' + path, {
      method, credentials: 'omit', redirect: 'error', cache: 'no-store',
      headers: {'Authorization': 'Bearer ' + this.token, 'Content-Type': 'application/json'},
      body: data === undefined ? undefined : JSON.stringify(data)
    });
    if (!response.ok) throw new Error('リクエストを処理できませんでした');
    return response.json();
  }
  list() { return this.request('/v1/notes'); }
  add(title, body) { return this.request('/v1/notes', 'POST', {title, body}); }
  contact(body) { return this.request('/v1/inquiries', 'POST', {body}); }
  export() { return this.request('/v1/exports', 'POST', {}); }
  logout() { this.token = ''; }
}
// Deliberately no automatic session acquisition or API activation in this fixture UI.
const backend = demo;
async function render() {
  nodes.notes.replaceChildren();
  for (const note of (await backend.list()).items) {
    const li = document.createElement('li');
    const title = document.createElement('strong'); title.textContent = note.title;
    const body = document.createElement('p'); body.textContent = note.body;
    li.append(title, body); nodes.notes.append(li);
  }
}
function safely(action) {
  return async event => {
    event.preventDefault(); nodes.error.textContent = '';
    try { await action(); } catch { nodes.error.textContent = '入力と権限を確認してください。'; }
  };
}
document.getElementById('note-form').addEventListener('submit', safely(async () => {
  await backend.add(nodes.title.value, nodes.body.value); await render();
}));
document.getElementById('contact-form').addEventListener('submit', safely(async () => {
  const {receipt_id} = await backend.contact(nodes.inquiry.value);
  nodes.receipt.textContent = '受け付けました。受付番号: ' + receipt_id;
}));
document.getElementById('export').addEventListener('click', safely(async () => {
  nodes.result.textContent = JSON.stringify(await backend.export(), null, 2);
}));
render();
