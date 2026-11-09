# CipherMesh — Threat Model (`THREAT-MODEL.md`)

This document defines the assets, trust boundaries, adversary profiles, mitigations, and residual risks of the CipherMesh platform.

---

## 1. Protected Assets

1. **Message Plaintext & Replies:** Confidential text conversations between peers.
2. **File Transfer Contents:** Binary files shared between peers.
3. **Long-Term Device Private Keys:** Ed25519 signing secret keys and X25519 Diffie-Hellman secret keys stored in the client browser.
4. **Session Integrity & Ordering:** Assurance that messages originate from the claimed contact, have not been modified in transit, and have not been replayed.

---

## 2. Trust Boundaries

| Component | Trust Level | Access Scope |
| :--- | :--- | :--- |
| **Local Browser Environment (`IndexedDB` + WebCrypto/CSPRNG)** | **Trusted Endpoint** | Holds private keys, performs encryption/decryption, renders plaintext. |
| **WebRTC Direct P2P DataChannel** | **Untrusted Network Link** | Carries DTLS-encrypted SCTP frames containing application-layer `XChaCha20-Poly1305` ciphertexts. |
| **STUN / TURN Relay Servers** | **Untrusted Infrastructure** | Observes IP addresses and encrypted packet timing; never sees plaintext or private keys. |
| **Supabase Backend (PostgreSQL + Realtime)** | **Untrusted for Plaintext / Semi-Trusted Directory** | Stores public keys, encrypted message envelopes, and routing metadata; enforces Row Level Security (RLS). |

---

## 3. Adversary Profiles & Mitigations

### Adversary A: Passive Network Eavesdropper / Malicious TURN Relay
- **Goal:** Read message content or transferred files traversing the network or TURN relay.
- **Mitigation:** Dual-layer encryption. Even if transport-layer DTLS were terminated or inspected, every message and 16 KB file chunk is independently encrypted on the client with `XChaCha20-Poly1305` using keys derived via `X25519 + HKDF-SHA256`.

### Adversary B: Compromised Database / Curious Cloud Operator
- **Goal:** Extract conversation history or private keys from PostgreSQL snapshots or server logs.
- **Mitigation:**
  - Private keys are never transmitted to the server.
  - `public.encrypted_messages` stores only `ciphertext`, `nonce`, `ephemeral_public_key`, and `signature`.
  - Automated integration tests explicitly verify that zero plaintext strings appear in database records.

### Adversary C: Active Man-in-the-Middle (Key Substitution Attack)
- **Goal:** Substitute a peer's public X25519 key in the directory to intercept messages.
- **Mitigation:**
  - Each device signs its X25519 public key with its Ed25519 identity key (`verifyKeyBindingSignature`).
  - CipherMesh clearly distinguishes **Connected (Unverified)** sessions from **Verified Identities**.
  - Users can compare 60-digit Safety Numbers or scan Identity QR codes out-of-band.
  - If a previously verified contact's fingerprint changes, CipherMesh triggers a prominent `identity_changed_warning` alert banner and logs a security event.

### Adversary D: Packet Replay & Ciphertext Tampering Attacker
- **Goal:** Re-inject captured encrypted messages or flip bits in ciphertext/headers.
- **Mitigation:**
  - Canonical AAD binds `conversationId`, `senderEd25519PublicKey`, `senderX25519PublicKey`, `ephemeralPublicKey`, `nonce`, `sequenceNumber`, and `sessionEpoch` into both the Poly1305 MAC and the Ed25519 signature.
  - `ReplayProtectionWindow` and database `UNIQUE` constraints reject duplicate nonces and duplicate `(conversation_id, sender_id, sequence_number, session_epoch)` tuples.

### Adversary E: Authenticated Cross-User Attacker (Mallory)
- **Goal:** Query or inject messages into conversations belonging to other users (Alice & Bob).
- **Mitigation:** Strict PostgreSQL Row Level Security (RLS) policies (`is_conversation_member(conversation_id, auth.uid())`) verified by automated security tests (`src/lib/__tests__/integration-security.test.ts`).

---

## 4. Residual Risks & Transparent Limitations

1. **Metadata Visibility:** Like any internet messaging system using store-and-forward and signaling, the coordination server necessarily processes routing metadata (`sender_id`, `recipient_id`, `conversation_id`, timestamps, and ciphertext byte length).
2. **Endpoint Compromise & XSS:** If an attacker compromises the user's operating system or injects malicious scripts into the browser origin, local keys and plaintext can be accessed. CipherMesh applies strict `Content-Security-Policy` headers to mitigate script injection.
3. **Ephemeral Message Boundaries:** Disappearing messages automatically purge records from the UI and filter expired rows at the database RLS layer, but cannot prevent a recipient from photographing their screen or copying text while visible.
