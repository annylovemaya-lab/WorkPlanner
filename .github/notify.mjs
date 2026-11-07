// Планер: отправка уведомлений (запускается GitHub Actions по расписанию).
// Читает приватный репозиторий с данными: sched.json (расписание от планера), subs.json (устройства),
// sent.json (что уже отправлено) и vapid.json (ключи; создаются при первом запуске).
const API = process.env.GH_API || 'https://api.github.com';
const REPO = process.env.DATA_REPO, TOKEN = process.env.DATA_TOKEN;
if (!REPO || !TOKEN) { console.error('Не заданы секреты DATA_REPO и DATA_TOKEN'); process.exit(1); }
const enc = new TextEncoder();
function b64u(buf) {
  let s = '';
  new Uint8Array(buf).forEach(b => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function concat(...a) {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
}
async function sha(t) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(t));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}


const H = { Authorization: 'Bearer ' + TOKEN, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
async function get(file) {
  const r = await fetch(`${API}/repos/${REPO}/contents/${file}`, { headers: H });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GET ${file}: ${r.status}`);
  const j = await r.json();
  return { sha: j.sha, data: JSON.parse(Buffer.from(j.content, 'base64').toString('utf8')) };
}
async function put(file, obj, sha) {
  const body = { message: 'planner notify', content: Buffer.from(JSON.stringify(obj)).toString('base64') };
  if (sha) body.sha = sha;
  const r = await fetch(`${API}/repos/${REPO}/contents/${file}`, { method: 'PUT', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`PUT ${file}: ${r.status}`);
}

let VAPID = null;
async function loadVapid() {
  let cur = await get('vapid.json');
  if (!cur) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const rec = { pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) };
    await put('vapid.json', rec);
    console.log('Ключи уведомлений созданы');
    cur = { data: rec };
  }
  const key = await crypto.subtle.importKey('jwk', cur.data.priv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  VAPID = { pub: cur.data.pub, key };
}
async function vapidJwt(aud, sub) {
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, VAPID.key, enc.encode(h + '.' + p));
  return h + '.' + p + '.' + b64u(sig);
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
// RFC 8291 (aes128gcm)
async function encryptPayload(sub, text) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, kp.privateKey, 256));
  const ikm = await hkdf(auth, secret, concat(enc.encode('WebPush: info\x00'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\x00'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\x00'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  const head = new Uint8Array(21);
  head.set(salt, 0);
  new DataView(head.buffer).setUint32(16, 4096);
  head[20] = 65;
  return concat(head, asPub, ct);
}
async function sendPush(sub, msg) {
  const aud = new URL(sub.endpoint).origin;
  const body = await encryptPayload(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      Authorization: 'vapid t=' + (await vapidJwt(aud, 'https://github.com/' + REPO.split('/')[0])) + ', k=' + VAPID.pub,
      'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '3600', Urgency: 'high'
    },
    body
  });
  return r.status;
}

async function main() {
  await loadVapid();
  const [sc, sb, st] = await Promise.all([get('sched.json'), get('subs.json'), get('sent.json')]);
  const sched = (sc && sc.data && sc.data.sched) || [], subs = ((sb && sb.data && sb.data.subs) || []).slice();
  const sent = (st && st.data && st.data.sent) || {};
  const now = Date.now();
  /* Расписание GitHub неточное, поэтому шлём чуть заранее (до 4 минут) и не позже часа после времени */
  const due = sched.filter(e => e.t <= now + 4 * 60000 && e.t > now - 60 * 60000 && !sent[e.id]);
  console.log(`в расписании ${sched.length}, к отправке ${due.length}, устройств ${subs.length}`);
  if (!due.length || !subs.length) return;
  const dead = new Set();
  for (const e of due) {
    sent[e.id] = now;
    for (const s of subs) {
      if (dead.has(s.endpoint)) continue;
      try {
        const code = await sendPush(s, { title: e.title, body: e.body, tag: e.id });
        console.log('push', e.id, code);
        if (code === 404 || code === 410) dead.add(s.endpoint);
      } catch (err) { console.log('ошибка отправки', e.id, err.message); }
    }
  }
  for (const k in sent) if (sent[k] < now - 3 * 864e5) delete sent[k];
  await put('sent.json', { sent }, st && st.sha);
  if (dead.size) {
    const fresh = await get('subs.json');
    await put('subs.json', { subs: ((fresh && fresh.data.subs) || []).filter(s => !dead.has(s.endpoint)) }, fresh && fresh.sha);
  }
}
main().catch(e => { console.error(e); process.exit(1); });
