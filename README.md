# RSA Digital Signature – Level 3 (three applications)

Three Node.js applications (no npm packages needed, Node 18+) that communicate over TCP sockets using JSON.

| App | File | Web UI | Role |
|-----|------|--------|------|
| 1 | `app1-sender.js` | http://localhost:3001 | Enter a message, SHA-256 hash it, sign the hash with the RSA private key, send message + signature + public key to App 2 (socket port 4002) |
| 2 | `app2-proxy.js` | http://localhost:3002 | Man-in-the-middle: receives the data, lets you edit the message/signature, forwards to App 3 (socket port 4003) |
| 3 | `app3-verifier.js` | http://localhost:3003 | Recovers the hash from the signature with the public key, hashes the received message, compares: VALID / INVALID |

## Run
Open three terminals in this folder, start App 3 first, then App 2, then App 1:

```
node app3-verifier.js
node app2-proxy.js
node app1-sender.js
```

Then in the browser: App 1 → **Sign message** → **Send**; App 2 → optionally **Tamper with signature** → **Forward**; App 3 shows the result.

Tests: `node test.js`

## Message format (JSON, one document per line)
```json
{ "message": "...", "signature": "<base64>", "publicKey": "-----BEGIN PUBLIC KEY-----..." }
```

## How it works
1. Sender: `hash = SHA-256(message)`, `signature = RSA_private(hash)` (RSA 2048, PKCS#1 v1.5).
2. Receiver: `recovered = RSA_public(signature)`, `hash' = SHA-256(received message)`.
3. Valid only if `recovered == hash'`. Changing the message changes `hash'`; changing the signature changes `recovered` (or breaks the padding). Without the private key an attacker cannot produce a signature that matches a new hash.
