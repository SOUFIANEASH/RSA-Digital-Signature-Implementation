// End-to-end test: starts the 3 apps, sends a message untouched and then tampered.
const { spawn } = require("child_process");
const assert = require("assert");
const L = require("./lib");

const post = (port, name, body) =>
  fetch(`http://localhost:${port}/api/${name}`, { method: "POST", body: JSON.stringify(body || {}) }).then((r) => r.json());
const get = (port) => fetch(`http://localhost:${port}/state`).then((r) => r.json());
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// unit check of the crypto
const { publicKey, privateKey } = L.generateKeys();
const s = L.sign("hello", privateKey);
assert.strictEqual(L.verify("hello", s, publicKey).valid, true);
assert.strictEqual(L.verify("hellO", s, publicKey).valid, false);
assert.strictEqual(L.verify("hello", s, publicKey).recoveredHash, L.sha256("hello"));

(async () => {
  const procs = ["app3-verifier.js", "app2-proxy.js", "app1-sender.js"].map((f) =>
    spawn(process.execPath, [f], { stdio: "ignore" }));
  try {
    await sleep(1500);
    await post(3001, "sign", { message: "Pay Soufiane 100 EUR" });
    await post(3001, "send");
    await sleep(500);
    const orig = (await get(3002)).received;
    assert.ok(orig && orig.signature);

    // 1) forward untouched -> valid
    assert.strictEqual((await post(3002, "forward", { message: orig.message, signature: orig.signature })).modified, false);
    await sleep(500);
    assert.strictEqual((await get(3003)).current.valid, true);

    // 2) tampered signature -> invalid
    const bad = orig.signature.slice(0, 20) + (orig.signature[20] === "A" ? "B" : "A") + orig.signature.slice(21);
    await post(3002, "forward", { message: orig.message, signature: bad });
    await sleep(500);
    assert.strictEqual((await get(3003)).current.valid, false);

    // 3) tampered message -> invalid
    await post(3002, "forward", { message: "Pay Soufiane 900 EUR", signature: orig.signature });
    await sleep(500);
    assert.strictEqual((await get(3003)).current.valid, false);
    console.log("all tests passed");
  } finally {
    procs.forEach((p) => p.kill());
  }
})().catch((e) => { console.error(e); process.exit(1); });
