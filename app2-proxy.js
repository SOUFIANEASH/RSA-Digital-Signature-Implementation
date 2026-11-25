// Application 2 - Tampering Proxy. Receives from App 1 (socket :4002), lets the user edit, forwards to App 3 (:4003).
const L = require("./lib");

const UI_PORT = +process.env.UI_PORT || 3002;
const LISTEN_PORT = +process.env.LISTEN_PORT || 4002;
const NEXT_HOST = process.env.NEXT_HOST || "127.0.0.1";
const NEXT_PORT = +process.env.NEXT_PORT || 4003;

let received = null; // original data from App 1
let version = 0;     // lets the UI refill its fields only when new data arrives

L.listenSocket(LISTEN_PORT, (data) => {
  received = data;
  version++;
  console.log("received message from App 1");
});

const body = `
<p id="status">Waiting for data from Application 1…</p>
<label for="msg">Message (editable)</label>
<textarea id="msg"></textarea>
<label for="sig">Digital signature, base64 (editable – change a character to simulate tampering)</label>
<textarea id="sig"></textarea>
<label>Public key (from App 1)</label><pre id="pub">—</pre>
<button onclick="tamper()">Tamper with signature</button>
<button onclick="reset()">Restore original</button>
<button onclick="fwd()">Forward to Application 3</button>
<p id="result"></p>`;

const script = `
let seen=0, orig=null;
async function poll(){
  const s=await state();
  if(s.version && s.version!==seen){ seen=s.version; orig=s.received;
    $('msg').value=orig.message; $('sig').value=orig.signature; $('pub').textContent=orig.publicKey;
    $('status').textContent='New data received from Application 1.'; $('result').textContent=''; }
}
function tamper(){ const v=$('sig').value; if(!v) return; const i=Math.floor(v.length/2);
  $('sig').value=v.slice(0,i)+(v[i]==='A'?'B':'A')+v.slice(i+1); }
function reset(){ if(orig){ $('msg').value=orig.message; $('sig').value=orig.signature; } }
async function fwd(){ const r=await api('forward',{message:$('msg').value,signature:$('sig').value});
  $('result').innerHTML=r.error?'<span class="err">'+r.error+'</span>':'Forwarded to Application 3 ('+(r.modified?'MODIFIED':'unmodified')+').'; }
setInterval(poll,1000); poll();`;

L.serveWeb(UI_PORT, L.pageHtml("Application 2 – Tampering Proxy", body, script), () => ({ version, received }), {
  forward: async ({ message, signature }) => {
    if (!received) throw new Error("Nothing received yet");
    await L.sendSocket(NEXT_HOST, NEXT_PORT, { message, signature, publicKey: received.publicKey });
    return { ok: true, modified: message !== received.message || signature !== received.signature };
  },
});
