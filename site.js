/* Short Options Filter -- static-site runtime (GitHub Pages copy).
 *
 * The website is the local app's own page (static/index.html, copied by
 * export_site.py) running without a server. This file loads before the page
 * script and:
 *   1. asks for the password and decrypts data.bin (AES-256-GCM, key from
 *      PBKDF2-SHA256), in the browser;
 *   2. answers the page's /api/* fetches from the decrypted data, and serves
 *      the day's xlsx from it for the Download button.
 * Nothing is sent anywhere; the data never leaves the browser decrypted.
 */
(function () {
'use strict';

const KEY_STORE = 'shortopts.key';
let resolveReady, rejectReady;
const READY = new Promise((res, rej) => { resolveReady = res; rejectReady = rej; });
let DATA = null;

const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function loadBlob() {
  const r = await fetch('data.bin', {cache: 'no-cache'});
  if (!r.ok) throw new Error('data.bin: HTTP ' + r.status);
  const buf = new Uint8Array(await r.arrayBuffer());
  const magic = String.fromCharCode(...buf.slice(0, 4));
  if (magic === 'SOF0') return {open: true, gz: buf.slice(4)};
  if (magic !== 'SOF1') throw new Error('unexpected data format');
  const dv = new DataView(buf.buffer);
  return {salt: buf.slice(4, 20), iv: buf.slice(20, 32), iter: dv.getUint32(32), ct: buf.slice(36)};
}

async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password),
                                             'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter}, base, 256);
}

async function inflate(bytes) {
  const text = await new Response(new Blob([bytes]).stream()
    .pipeThrough(new DecompressionStream('gzip'))).text();
  return JSON.parse(text);
}

async function openWith(rawKey, blob) {
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({name: 'AES-GCM', iv: blob.iv}, key, blob.ct);
  return inflate(plain);
}

function gateUI() {
  const wrap = document.createElement('div');
  wrap.id = 'gate';
  wrap.innerHTML = `
    <style>
      #gate{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;
        background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}
      #gate form{background:var(--panel);border:1px solid var(--line);border-radius:10px;
        padding:26px 28px;width:min(360px,90vw);box-shadow:0 10px 40px rgba(0,0,0,.25)}
      #gate h2{margin:0 0 6px;font-size:18px}
      #gate p{margin:0 0 16px;color:var(--muted);font-size:13px;line-height:1.45}
      #gate input[type=password]{width:100%;box-sizing:border-box;padding:9px 11px;font-size:15px;
        border:1px solid var(--line);border-radius:6px;margin-bottom:10px;background:var(--bg);color:var(--ink)}
      #gate label{display:flex;gap:6px;align-items:center;font-size:12px;color:var(--muted)}
      #gate button{margin-top:14px;width:100%;padding:9px;font-size:14px;font-weight:600;border-radius:6px;
        border:0;background:var(--accent);color:#fff;cursor:pointer}
      #gate .err{color:var(--dn);font-size:12px;min-height:16px;margin-top:8px}
    </style>
    <form autocomplete="on">
      <h2>Short Options Filter</h2>
      <p>This site's data is encrypted. Enter the password to unlock it. It is
         decrypted in your browser and never sent anywhere.</p>
      <input type="text" name="username" value="short-options" autocomplete="username" hidden>
      <input type="password" id="gate-pw" autocomplete="current-password" placeholder="Password" required autofocus>
      <label><input type="checkbox" id="gate-remember"> Remember on this device</label>
      <button type="submit" id="gate-go">Unlock</button>
      <div class="err" id="gate-err"></div>
    </form>`;
  return wrap;
}

async function unlock() {
  let blob;
  try { blob = await loadBlob(); }
  catch (e) { rejectReady(e); return; }
  if (blob.open) {
    try { DATA = await inflate(blob.gz); resolveReady(); } catch (e) { rejectReady(e); }
    return;
  }
  for (const store of [sessionStorage, localStorage]) {
    let k = null;
    try { k = store.getItem(KEY_STORE); } catch (e) {}
    if (!k) continue;
    try { DATA = await openWith(unb64(k), blob); resolveReady(); return; }
    catch (e) { try { store.removeItem(KEY_STORE); } catch (e2) {} }
  }
  const ui = gateUI();
  document.body.appendChild(ui);
  const form = ui.querySelector('form'), err = ui.querySelector('#gate-err'), go = ui.querySelector('#gate-go');
  form.onsubmit = async ev => {
    ev.preventDefault();
    go.disabled = true; go.textContent = 'Unlocking...'; err.textContent = '';
    try {
      const raw = await deriveKey(ui.querySelector('#gate-pw').value, blob.salt, blob.iter);
      DATA = await openWith(raw, blob);
      try {
        sessionStorage.setItem(KEY_STORE, b64(raw));
        if (ui.querySelector('#gate-remember').checked) localStorage.setItem(KEY_STORE, b64(raw));
      } catch (e) {}
      ui.remove();
      resolveReady();
    } catch (e) {
      err.textContent = 'Wrong password.';
      go.disabled = false; go.textContent = 'Unlock';
    }
  };
}

const json = obj => new Response(JSON.stringify(obj), {headers: {'Content-Type': 'application/json'}});
const realFetch = window.fetch.bind(window);
window.fetch = async (url, opts) => {
  const u = String(url);
  if (!u.startsWith('/api/')) return realFetch(url, opts);
  await READY;
  if (u.startsWith('/api/latest')) return json(DATA.latest);
  if (u.startsWith('/api/files')) return json(DATA.xlsx ? [DATA.xlsx.name] : []);
  if (u.startsWith('/api/status')) return json({
    job: {running: false}, log: [],
    task: {state: 'Website copy, rebuilt by the daily run (published ' + DATA.built + ')'}});
  return json({ok: false, msg: 'not available on the website'});
};

window.downloadXlsx = async name => {
  await READY;
  if (!DATA.xlsx || DATA.xlsx.name !== name) return;
  const blob = new Blob([unb64(DATA.xlsx.b64)],
    {type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
};

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', unlock);
else unlock();
})();
