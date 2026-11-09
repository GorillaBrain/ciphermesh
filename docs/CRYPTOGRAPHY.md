# CipherMesh — Cryptographic Specification (`CRYPTOGRAPHY.md`)

CipherMesh implements a documented, testable cryptographic architecture built exclusively on audited primitives from the `@noble/*` cryptographic suite (authored by Paul Miller and audited by Cure53). No custom cryptographic primitives or unreviewed algorithms are used.

---

## 1. Cryptographic Suite Summary

| Function | Algorithm / Construction | Library Module | Key / Nonce Size |
| :--- | :--- | :--- | :--- |
| **Identity & Transcript Signatures** | Ed25519 (RFC 8032) | `@noble/curves/ed25519.js` | 256-bit key, 512-bit signature |
| **Diffie-Hellman Key Agreement** | X25519 (RFC 7748) | `@noble/curves/ed25519.js` | 256-bit scalar / point |
| **Key Derivation Function (KDF)** | HKDF-SHA256 (RFC 5869) | `@noble/hashes/hkdf.js` | 256-bit derived symmetric key |
| **Authenticated Encryption (AEAD)** | XChaCha20-Poly1305 | `@noble/ciphers/chacha.js` | 256-bit key, 192-bit (24B) nonce, 128-bit tag |
| **Fingerprints, Safety Numbers & File Integrity** | SHA-256 (FIPS 180-4) | `@noble/hashes/sha2.js` | 256-bit digest |

---

## 2. Device Identity Generation & Key Binding

When a user registers or provisions a new workstation (`generateDeviceIdentity` in [`src/lib/crypto/engine.ts`](../src/lib/crypto/engine.ts)):
1. A 32-byte Ed25519 signing keypair `(edSecret, edPublic)` is generated.
2. A 32-byte X25519 Diffie-Hellman keypair `(xSecret, xPublic)` is generated.
3. To prevent key-substitution attacks, the Ed25519 secret key signs a domain-separated binding transcript:
   ```
   CipherMesh-v1:key-bind:<ed25519PublicKeyHex>:<x25519PublicKeyHex>:v<keyVersion>
   ```
4. The public identity fingerprint is computed as the uppercase hex representation of the first 128 bits of:
   ```
   SHA256("CipherMesh-v1:fingerprint:<ed25519PublicKeyHex>:<x25519PublicKeyHex>")
   ```
   formatted in eight 4-character blocks (e.g., `8F4A 9C12 3D7B E04F ...`).

---

## 3. Message Key Derivation & Authenticated Encryption

For every message in conversation `conversationId` at `sequenceNumber` and `sessionEpoch`:

1. **Fresh Entropy Generation:**
   - A fresh 24-byte (192-bit) random nonce $N$ is generated via `randomBytes(24)`.
   - A fresh 32-byte ephemeral X25519 keypair $(e_{priv}, E_{pub})$ is generated.
2. **X25519 Shared Secret & HKDF-SHA256 Derivation:**
   - The static ECDH shared secret $S = \text{X25519}(x_{priv}, X_{peer\_pub})$ is computed.
   - The HKDF salt incorporates the per-message ephemeral public key $E_{pub}$, `conversationId`, and `sessionEpoch`:
     ```
     salt = SHA256(E_pub || UTF8(conversationId + ":epoch:" + sessionEpoch))
     info = UTF8("CipherMesh-v1:message-key:seq:" + sequenceNumber + ":epoch:" + sessionEpoch)
     K_msg = HKDF-SHA256(ikm = S, salt = salt, info = info, length = 32)
     ```
   - Sensitive intermediate buffers ($S$, $x_{priv}$) are zeroized in memory immediately after derivation using `clean()`.
3. **Canonical Associated Authenticated Data (AAD):**
   ```
   AAD = UTF8("CipherMesh-v1|<conversationId>|<senderEd25519Pub>|<senderX25519Pub>|<ephemeralPub>|<nonceHex>|seq:<sequenceNumber>|epoch:<sessionEpoch>")
   ```
4. **XChaCha20-Poly1305 Encryption & Ed25519 Transcript Signature:**
   - The JSON payload is encrypted and authenticated with `xchacha20poly1305(K_msg, N, AAD)`.
   - The sender signs `concatBytes(AAD, ciphertextBytes)` with their Ed25519 identity secret key.
   - On decryption, the recipient **first** verifies the Ed25519 signature over `AAD || ciphertextBytes` before invoking `xchacha20poly1305.decrypt`.

---

## 4. Replay Protection & Out-of-Order Handling

`ReplayProtectionWindow` in [`src/lib/crypto/engine.ts`](../src/lib/crypto/engine.ts) enforces:
- **Nonce Deduplication:** Every seen 192-bit nonce hex is recorded; any duplicate nonce is immediately rejected.
- **Per-Epoch Sequence Tracking:** Every `(senderId, sessionEpoch, sequenceNumber)` tuple is tracked within a sliding window (default 2,048 messages). Duplicate sequence numbers are rejected as replay attacks, while delayed messages arriving out-of-order within the window are safely decrypted using their deterministic sequence-bound HKDF parameters.
- **Database Constraint Enforcement:** `public.encrypted_messages` also enforces `UNIQUE(conversation_id, sender_id, sequence_number, session_epoch)` at the PostgreSQL layer.

---

## 5. Contact Safety Numbers

To allow two peers (Alice and Bob) to verify that no Man-in-the-Middle (MitM) has substituted their public keys, `computeSafetyNumber` canonicalizes both peers' `(userId, ed25519PublicKeyHex, x25519PublicKeyHex)` tuples in lexicographical order so `SafetyNumber(Alice, Bob) === SafetyNumber(Bob, Alice)`. Twelve rounds of domain-separated SHA-256 hashing produce **12 blocks of 5 digits (60 digits total)**.

---

## 6. Honest Cryptographic Limitations

- **Protocol Classification:** CipherMesh implements an authenticated X25519 + per-message ephemeral HKDF-SHA256 + XChaCha20-Poly1305 + Ed25519 protocol with explicit session epoch rotation. It **does not** claim Signal Double Ratchet protocol compatibility or continuous post-compromise security (PCS) if a device's static IndexedDB keystore is exfiltrated without a subsequent device key rotation.
- **Browser Keystore Boundary:** Because CipherMesh is a web application, local private keys reside in browser storage (`IndexedDB`). Physical compromise or malicious browser extensions with origin access could read local storage.
