// Shared helpers: RSA signing/verification, JSON-over-TCP sockets, tiny web UI server.
const crypto = require("crypto");
const net = require("net");
const http = require("http");

// ---------- RSA digital signature (hash with SHA-256, sign hash with private key) ----------
function generateKeys() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

const sha256 = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

/** Signature = RSA_private(SHA-256(message)), returned as base64. */
function sign(message, privateKeyPem) {
  return crypto.sign("sha256", Buffer.from(message, "utf8"), privateKeyPem).toString("base64");
}

/**
 * Verification: (1) recover the hash from the signature with the public key,
 * (2) hash the received message, (3) compare. crypto.verify does this check.
 */
function verify(message, signatureB64, publicKeyPem) {
  const hash = sha256(message);
  let valid = false;
  let recoveredHash = null;
  const sig = Buffer.from(String(signatureB64), "base64");
  try {
    valid = crypto.verify("sha256", Buffer.from(message, "utf8"), publicKeyPem, sig);
  } catch (_) { valid = false; }
  try {
    // PKCS#1 v1.5 block ends with the 32-byte SHA-256 digest
    recoveredHash = crypto
      .publicDecrypt({ key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING }, sig)
      .subarray(-32).toString("hex");
  } catch (_) { recoveredHash = null; }
  return { valid, hash, recoveredHash };
}

// ---------- sockets: one JSON document per line over TCP ----------
function listenSocket(port, onMessage) {
  const server = net.createServer((sock) => {
    let buf = "";
    sock.on("data", (chunk) => {
      buf += chunk;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        try { onMessage(JSON.parse(line)); } catch (e) { console.error("Bad message:", e.message); }
      }
    });
    sock.on("error", () => {});
  });
  server.listen(port, () => console.log(`socket server listening on :${port}`));
  return server;
}

function sendSocket(host, port, obj) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, host, () => s.end(JSON.stringify(obj) + "\n"));
    s.on("error", (e) => reject(new Error(`Cannot reach ${host}:${port} (${e.code}). Is the next app running?`)));
    s.on("close", resolve);
  });
}

// ---------- tiny web UI server ----------
function pageHtml(title, body, script) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 16px;color:#222}
h1{font-size:1.4rem} label{display:block;margin:12px 0 4px;font-size:.85rem;color:#445}
textarea{width:100%;box-sizing:border-box;padding:8px;font:.85rem ui-monospace,monospace;border:1px solid #aab;border-radius:5px;min-height:80px}
button{margin:10px 8px 0 0;padding:8px 16px;border:0;border-radius:5px;background:#2b4acb;color:#fff;font:inherit;cursor:pointer}
pre{background:#eef;padding:10px;border-radius:5px;white-space:pre-wrap;word-break:break-all;font-size:.8rem}
.badge{display:inline-block;padding:8px 18px;border-radius:6px;font-weight:700;color:#fff;margin:8px 0}
.valid{background:#0a7a32}.invalid{background:#b00020}.err{color:#b00020}
</style></head><body><h1>${title}</h1>${body}
<script>
const $=id=>document.getElementById(id);
const api=(n,b)=>fetch('/api/'+n,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(r=>r.json());
const state=()=>fetch('/state').then(r=>r.json());
${script}
</script></body></html>`;
}

function serveWeb(port, html, getState, actions) {
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/state") {
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify(getState()));
    }
    if (req.method === "GET" && req.url === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(html);
    }
    const m = /^\/api\/(\w+)$/.exec(req.url);
    if (req.method === "POST" && m && actions[m[1]]) {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        res.setHeader("Content-Type", "application/json");
        try { res.end(JSON.stringify(await actions[m[1]](body ? JSON.parse(body) : {}))); }
        catch (e) { res.statusCode = 400; res.end(JSON.stringify({ error: e.message })); }
      });
      return;
    }
    res.statusCode = 404; res.end("Not found");
  });
  server.listen(port, () => console.log(`web UI: http://localhost:${port}`));
  return server;
}

module.exports = { generateKeys, sha256, sign, verify, listenSocket, sendSocket, pageHtml, serveWeb };
