// Application 3 - Verification. Receives from App 2 (socket :4003) and verifies the RSA signature.
const L = require("./lib");

const UI_PORT = +process.env.UI_PORT || 3003;
const LISTEN_PORT = +process.env.LISTEN_PORT || 4003;

let current = null;
let version = 0;

L.listenSocket(LISTEN_PORT, (data) => {
  const v = L.verify(data.message, data.signature, data.publicKey);
  current = { ...data, ...v };
  version++;
  console.log("verification:", v.valid ? "VALID" : "INVALID");
});

const body = `
<p id="status">Waiting for data from Application 2…</p>
<div id="badge"></div>
<label>Received message</label><pre id="msg">—</pre>
<label>Received signature (base64)</label><pre id="sig">—</pre>
<label>Hash recovered from the signature (decrypted with public key)</label><pre id="rec">—</pre>
<label>SHA-256 hash computed from the received message</label><pre id="hash">—</pre>
<label>Public key</label><pre id="pub">—</pre>`;

const script = `
let seen=0;
async function poll(){
  const s=await state(); if(!s.version||s.version===seen) return; seen=s.version; const c=s.current;
  $('status').textContent='Data received.';
  $('badge').innerHTML=c.valid?'<span class="badge valid">VALID – message not altered</span>':'<span class="badge invalid">INVALID – message or signature was tampered with</span>';
  $('msg').textContent=c.message; $('sig').textContent=c.signature;
  $('rec').textContent=c.recoveredHash||'(could not recover a hash: signature is corrupted)';
  $('hash').textContent=c.hash; $('pub').textContent=c.publicKey;
}
setInterval(poll,1000); poll();`;

L.serveWeb(UI_PORT, L.pageHtml("Application 3 – Verification", body, script), () => ({ version, current }), {});
