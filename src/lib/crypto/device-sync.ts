/**
 * Device Identity Registration & Synchronization Helper
 *
 * Ensures the current authenticated user's local device identity (Ed25519 + X25519)
 * is generated in local IndexedDB/localStorage and its PUBLIC keys are registered
 * in `public.devices` and `public.identity_public_keys`.
 *
 * Secret keys NEVER leave the client.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import {
  getOrCreateLocalDeviceIdentity,
  rotateLocalDeviceIdentityKeys,
  saveLocalDeviceIdentity,
} from "../crypto/keystore";
import type { DeviceIdentityBundle } from "../crypto/engine";

export async function ensureDeviceRegisteredWithBackend(
  supabase: SupabaseClient,
  userId: string,
  customDeviceLabel?: string
): Promise<DeviceIdentityBundle> {
  const { bundle, isNewlyGenerated } = await getOrCreateLocalDeviceIdentity(
    userId,
    customDeviceLabel
  );

  const userAgent =
    typeof navigator !== "undefined" ? navigator.userAgent.slice(0, 200) : "";

  // Check if device with this fingerprint already exists for user
  const { data: existingDevice } = await supabase
    .from("devices")
    .select("*")
    .eq("user_id", userId)
    .eq("fingerprint", bundle.fingerprint)
    .maybeSingle();

  if (existingDevice) {
    // Update local bundle's deviceId if backend assigned UUID differs
    if (existingDevice.id !== bundle.deviceId) {
      bundle.deviceId = existingDevice.id;
      await saveLocalDeviceIdentity(userId, bundle);
    }

    await supabase
      .from("devices")
      .update({
        last_active_at: new Date().toISOString(),
        is_revoked: false,
      })
      .eq("id", existingDevice.id);

    return bundle;
  }

  // Insert new device record
  const { data: insertedDevice, error: deviceErr } = await supabase
    .from("devices")
    .insert({
      id: bundle.deviceId,
      user_id: userId,
      device_label: bundle.deviceLabel,
      user_agent: userAgent,
      ed25519_public_key: bundle.ed25519PublicKeyHex,
      x25519_public_key: bundle.x25519PublicKeyHex,
      fingerprint: bundle.fingerprint,
      is_revoked: false,
      verified_by_owner: true,
    })
    .select("*")
    .single();

  const finalDeviceId = insertedDevice?.id ?? bundle.deviceId;
  if (insertedDevice && insertedDevice.id !== bundle.deviceId) {
    bundle.deviceId = insertedDevice.id;
    await saveLocalDeviceIdentity(userId, bundle);
  }

  if (!deviceErr) {
    // Register in identity_public_keys
    await supabase.from("identity_public_keys").insert({
      user_id: userId,
      device_id: finalDeviceId,
      ed25519_public_key: bundle.ed25519PublicKeyHex,
      x25519_public_key: bundle.x25519PublicKeyHex,
      key_signature: bundle.keySignatureHex,
      fingerprint: bundle.fingerprint,
      key_version: bundle.keyVersion,
      is_active: true,
    });

    // Log security event
    await supabase.from("security_events").insert({
      user_id: userId,
      device_id: finalDeviceId,
      event_type: "device_registered",
      severity: "info",
      title: isNewlyGenerated
        ? "New Cryptographic Device Identity Registered"
        : "Device Identity Synchronized",
      description: `Device "${bundle.deviceLabel}" registered public key fingerprint ${bundle.fingerprint}. Private keys remain exclusively in local keystore.`,
      metadata: {
        fingerprint: bundle.fingerprint,
        device_label: bundle.deviceLabel,
        key_version: bundle.keyVersion,
        algorithm: "Ed25519 + X25519",
      },
    });
  }

  return bundle;
}

export async function rotateAndPublishDeviceKeys(
  supabase: SupabaseClient,
  userId: string
): Promise<DeviceIdentityBundle> {
  const rotated = await rotateLocalDeviceIdentityKeys(userId);

  // Deactivate previous active keys for this device
  await supabase
    .from("identity_public_keys")
    .update({
      is_active: false,
      rotated_at: new Date().toISOString(),
    })
    .eq("user_id", userId)
    .eq("device_id", rotated.deviceId)
    .eq("is_active", true);

  // Update device record with new keys and fingerprint
  await supabase
    .from("devices")
    .update({
      ed25519_public_key: rotated.ed25519PublicKeyHex,
      x25519_public_key: rotated.x25519PublicKeyHex,
      fingerprint: rotated.fingerprint,
      last_active_at: new Date().toISOString(),
    })
    .eq("id", rotated.deviceId)
    .eq("user_id", userId);

  // Insert new public key version
  await supabase.from("identity_public_keys").insert({
    user_id: userId,
    device_id: rotated.deviceId,
    ed25519_public_key: rotated.ed25519PublicKeyHex,
    x25519_public_key: rotated.x25519PublicKeyHex,
    key_signature: rotated.keySignatureHex,
    fingerprint: rotated.fingerprint,
    key_version: rotated.keyVersion,
    is_active: true,
  });

  // Record security event
  await supabase.from("security_events").insert({
    user_id: userId,
    device_id: rotated.deviceId,
    event_type: "key_rotated",
    severity: "info",
    title: `Device Identity Keys Rotated (v${rotated.keyVersion})`,
    description: `Generated new Ed25519 + X25519 keypair for "${rotated.deviceLabel}" with fingerprint ${rotated.fingerprint}.`,
    metadata: {
      fingerprint: rotated.fingerprint,
      key_version: rotated.keyVersion,
    },
  });

  return rotated;
}
