export interface UserProfile {
  id: string;
  username: string;
  display_name: string;
  avatar_color: string;
  bio: string;
  status_text: string;
  created_at: string;
  updated_at: string;
}

export interface DeviceRecord {
  id: string;
  user_id: string;
  device_label: string;
  user_agent: string;
  ed25519_public_key: string;
  x25519_public_key: string;
  fingerprint: string;
  is_revoked: boolean;
  verified_by_owner: boolean;
  registered_at: string;
  last_active_at: string;
}

export interface IdentityPublicKeyRecord {
  id: string;
  user_id: string;
  device_id: string;
  ed25519_public_key: string;
  x25519_public_key: string;
  key_signature: string;
  fingerprint: string;
  key_version: number;
  is_active: boolean;
  created_at: string;
  rotated_at: string | null;
}

export interface ContactVerificationRecord {
  id: string;
  verifier_user_id: string;
  contact_user_id: string;
  contact_device_id: string | null;
  verified_fingerprint: string;
  safety_number: string;
  verification_method: "manual" | "qr_scan" | "out_of_band";
  is_verified: boolean;
  verified_at: string;
}

export interface ConversationRecord {
  id: string;
  created_by: string;
  ephemeral_ttl_seconds: number | null;
  session_epoch: number;
  last_key_rotation_at: string;
  created_at: string;
  updated_at: string;
}

export interface EncryptedMessageRecord {
  id: string;
  conversation_id: string;
  sender_id: string;
  sender_device_id: string | null;
  recipient_id: string | null;
  ciphertext: string;
  nonce: string;
  ephemeral_public_key: string;
  sender_ed25519_public_key: string;
  sender_x25519_public_key: string;
  signature: string;
  sequence_number: number;
  session_epoch: number;
  algorithm: string;
  message_type:
    | "text"
    | "file_manifest"
    | "key_rotation"
    | "ephemeral_update"
    | "system";
  reply_to_id: string | null;
  transport_mode: "webrtc_p2p" | "webrtc_turn" | "store_and_forward";
  ephemeral_ttl_seconds: number | null;
  expires_at: string | null;
  is_deleted: boolean;
  created_at: string;
}

export interface MessageReceiptRecord {
  id: string;
  message_id: string;
  conversation_id: string;
  recipient_id: string;
  recipient_device_id: string | null;
  status: "delivered" | "read" | "expired";
  updated_at: string;
}

export interface SecurityEventRecord {
  id: string;
  user_id: string;
  peer_user_id: string | null;
  device_id: string | null;
  conversation_id: string | null;
  event_type:
    | "device_registered"
    | "device_revoked"
    | "identity_verified"
    | "identity_changed_warning"
    | "key_rotated"
    | "session_established"
    | "session_terminated"
    | "auth_failure_detected"
    | "replay_blocked"
    | "ephemeral_policy_changed"
    | "file_transfer_verified";
  severity: "info" | "success" | "warning" | "critical";
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface UserPreferencesRecord {
  user_id: string;
  auto_key_rotation_messages: number;
  default_ephemeral_ttl: number | null;
  require_verified_for_files: boolean;
  allow_turn_relay: boolean;
  force_turn_relay: boolean;
  show_typing_indicators: boolean;
  show_read_receipts: boolean;
  max_file_size_mb: number;
  updated_at: string;
}
