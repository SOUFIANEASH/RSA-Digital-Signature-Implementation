// Application 1 - Signing & Sending. UI on :3001, sends JSON to App 2 (proxy) over a TCP socket.
const L = require("./lib");

const UI_PORT = +process.env.UI_PORT || 3001;
const NEXT_HOST = process.env.NEXT_HOST || "127.0.0.1";
const NEXT_PORT = +process.env.NEXT_PORT || 4002;

const { publicKey, privateKey } = L.generateKeys();
let last = null;

const body = `
<label for="msg">Message</label>
<textarea id="msg">Pay Soufiane 100 EUR</textarea>
<button onclick="doSign()">1. Sign message</button>
<button onclick="doSend()">2. Send to Application 2</button>
<p id="status"></p>
<label>SHA-256 hash of the message</label><pre id="hash">—</pre>
<label>Digital signature (base64) = hash encrypted with the private key</label><pre id="sig">—</pre>
<label>Public key (sent with the message)</label><pre id="pub">—</pre>`;

const script = `
function show(s){ $('hash').textContent=s.hash; $('sig').textContent=s.signature; $('pub').textContent=s.publicKey; }
async function doSign(){ const r=await api('sign',{message:$('msg').value}); show(r); $('status').textContent='Signed.'; }
async function doSend(){ const r=await api('send'); $('status').innerHTML=r.error?'<span class="err">'+r.error+'</span>':'Sent over socket to Application 2.'; }
state().then(s=>{ if(s.signature) show(s); });`;

L.serveWeb(UI_PORT, L.pageHtml("Application 1 – Signing & Sending", body, script), () => last || {}, {
  sign: ({ message }) => {
    if (typeof message !== "string" || !message) throw new Error("Enter a message");
    last = { message, hash: L.sha256(message), signature: L.sign(message, privateKey), publicKey };
    return last;
  },
  send: async () => {
    if (!last) throw new Error("Sign a message first");
    await L.sendSocket(NEXT_HOST, NEXT_PORT, { message: last.message, signature: last.signature, publicKey: last.publicKey });
    return { ok: true };
  },
});
