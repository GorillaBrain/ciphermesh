# CipherMesh — Database Schema & Metadata Disclosure (`DATABASE.md`)

CipherMesh uses a normalized PostgreSQL schema hosted on Supabase with strict Row Level Security (RLS) enabled on every table.

---

## 1. Normalized Schema Overview

1. **`public.profiles`**
   - Stores public operator directory metadata (`id`, `username`, `display_name`, `avatar_color`, `bio`, `status_text`).
2. **`public.devices`**
   - Stores registered client devices per user (`id`, `user_id`, `device_label`, `ed25519_public_key`, `x25519_public_key`, `fingerprint`, `is_revoked`, `registered_at`, `last_active_at`).
   - **Never stores private keys.**
3. **`public.identity_public_keys`**
   - Versioned cryptographic key registry (`device_id`, `ed25519_public_key`, `x25519_public_key`, `key_signature`, `fingerprint`, `key_version`, `is_active`, `rotated_at`).
4. **`public.device_revocations`**
   - Audit log of revoked devices (`user_id`, `device_id`, `revoked_fingerprint`, `reason`, `revoked_at`).
5. **`public.contact_verifications`**
   - User-specific cryptographic verification records (`verifier_user_id`, `contact_user_id`, `verified_fingerprint`, `safety_number`, `verification_method`, `verified_at`).
6. **`public.conversations`**
   - Conversation container (`id`, `created_by`, `ephemeral_ttl_seconds`, `session_epoch`, `last_key_rotation_at`).
7. **`public.conversation_members`**
   - Many-to-many membership mapping (`conversation_id`, `user_id`, `joined_at`, `last_read_at`).
8. **`public.encrypted_messages`**
   - Stores **only** encrypted envelopes (`ciphertext`, `nonce`, `ephemeral_public_key`, `sender_ed25519_public_key`, `sender_x25519_public_key`, `signature`, `sequence_number`, `session_epoch`, `algorithm`, `transport_mode`, `expires_at`).
   - Enforces `UNIQUE(conversation_id, sender_id, sequence_number, session_epoch)` to block replay insertion.
9. **`public.message_receipts`**
   - Tracks `delivered` and `read` acknowledgments per recipient (`message_id`, `conversation_id`, `recipient_id`, `status`).
10. **`public.security_events`**
    - Real-time security telemetry log (`user_id`, `event_type`, `severity`, `title`, `description`, `metadata`).
11. **`public.user_preferences`**
    - Per-user security and transport settings (`max_file_size_mb`, `default_ephemeral_ttl`, `allow_turn_relay`, `force_turn_relay`, `show_typing_indicators`, `show_read_receipts`).

---

## 2. Row Level Security (RLS) Summary

- **`conversations`, `conversation_members`, `encrypted_messages`, `message_receipts`:** Restricted via security-definer helper `public.is_conversation_member(conversation_id, auth.uid())`. Non-members cannot read, insert, update, or delete any conversation or message rows.
- **Ephemeral Expiry Enforcement in RLS:** The `SELECT` policy on `public.encrypted_messages` enforces `(expires_at IS NULL OR expires_at > NOW())`, ensuring expired messages cannot be queried even before background cleanup runs.
- **`devices`, `identity_public_keys`:** Public keys are readable by authenticated users for E2EE key lookup, but `INSERT` / `UPDATE` / `DELETE` are strictly restricted to `auth.uid() = user_id`.
- **`contact_verifications`, `security_events`, `user_preferences`:** Strictly private to the owning user (`auth.uid() = user_id` / `verifier_user_id`).

---

## 3. Honest Metadata Disclosure

While CipherMesh never stores plaintext messages, private keys, or unencrypted files, the database necessarily processes the following metadata to route encrypted envelopes and coordinate sessions:
- Account identifiers (`user_id`, `username`)
- Conversation membership (`conversation_id`, `user_id`)
- Message envelope timestamps (`created_at`, `expires_at`), sequence numbers, and ciphertext byte lengths
- Device registration timestamps and public key fingerprints
