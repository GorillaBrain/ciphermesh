import { describe, it, expect, beforeAll } from "vitest";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import {
  generateDeviceIdentity,
  encryptMessageForPeer,
  decryptMessageEnvelope,
  computeSafetyNumber,
  splitAndEncryptFile,
  decryptAndReassembleFile,
} from "../crypto/engine";

const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL ||
  "https://bwgilftdthajqenyocet.supabase.co";
const SUPABASE_ANON_KEY =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ3Z2lsZnRkdGhhanFlbnlvY2V0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQyMzI3NTcsImV4cCI6MjEwOTgwODc1N30.os0FeXvZ6-U4OvdvqRn2up8f2rKdhI9AYzkCOY8alMA";

function createIsolatedClient(): SupabaseClient {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}

describe("CipherMesh Integration & Security Verification Suite (Live Supabase + RLS)", () => {
  const runId = Date.now().toString().slice(-6);
  const aliceEmail = `alice_int_${runId}@ciphermesh.sec`;
  const bobEmail = `bob_int_${runId}@ciphermesh.sec`;
  const malloryEmail = `mallory_int_${runId}@ciphermesh.sec`;
  const password = "CipherMesh_TestPass_2026!";

  let aliceClient: SupabaseClient;
  let bobClient: SupabaseClient;
  let malloryClient: SupabaseClient;

  let aliceUserId = "";
  let bobUserId = "";
  let malloryUserId = "";

  const aliceDevice = generateDeviceIdentity("Alice Integration Node", 1);
  const bobDevice = generateDeviceIdentity("Bob Integration Node", 1);
  const malloryDevice = generateDeviceIdentity("Mallory Node", 1);

  let conversationId = "";

  beforeAll(async () => {
    aliceClient = createIsolatedClient();
    bobClient = createIsolatedClient();
    malloryClient = createIsolatedClient();
  });

  it("registers Alice, Bob, and Mallory independently and provisions public device identities", async () => {
    const [aliceRes, bobRes, malloryRes] = await Promise.all([
      aliceClient.auth.signUp({
        email: aliceEmail,
        password,
        options: {
          data: {
            username: `alice_${runId}`,
            display_name: "Alice Vance",
          },
        },
      }),
      bobClient.auth.signUp({
        email: bobEmail,
        password,
        options: {
          data: {
            username: `bob_${runId}`,
            display_name: "Bob Mercer",
          },
        },
      }),
      malloryClient.auth.signUp({
        email: malloryEmail,
        password,
        options: {
          data: {
            username: `mallory_${runId}`,
            display_name: "Mallory Outsider",
          },
        },
      }),
    ]);

    expect(aliceRes.error).toBeNull();
    expect(bobRes.error).toBeNull();
    expect(malloryRes.error).toBeNull();

    aliceUserId = aliceRes.data.user!.id;
    bobUserId = bobRes.data.user!.id;
    malloryUserId = malloryRes.data.user!.id;

    // Register public device keys for Alice and Bob
    const { error: aliceDevErr } = await aliceClient.from("devices").insert({
      id: aliceDevice.deviceId,
      user_id: aliceUserId,
      device_label: aliceDevice.deviceLabel,
      ed25519_public_key: aliceDevice.ed25519PublicKeyHex,
      x25519_public_key: aliceDevice.x25519PublicKeyHex,
      fingerprint: aliceDevice.fingerprint,
    });
    expect(aliceDevErr).toBeNull();

    const { error: bobDevErr } = await bobClient.from("devices").insert({
      id: bobDevice.deviceId,
      user_id: bobUserId,
      device_label: bobDevice.deviceLabel,
      ed25519_public_key: bobDevice.ed25519PublicKeyHex,
      x25519_public_key: bobDevice.x25519PublicKeyHex,
      fingerprint: bobDevice.fingerprint,
    });
    expect(bobDevErr).toBeNull();
  }, 20000);

  it("creates an authenticated 1-to-1 conversation and delivers client-side encrypted messages with zero plaintext in DB", async () => {
    const { data: convId, error: rpcErr } = await aliceClient.rpc(
      "get_or_create_direct_conversation",
      { peer_id: bobUserId }
    );
    expect(rpcErr).toBeNull();
    expect(convId).toBeTruthy();
    conversationId = convId as string;

    const secretPlaintext =
      "TOP_SECRET_QUANTUM_TELEMETRY_PAYLOAD_DO_NOT_LEAK_99481";
    const envelope = encryptMessageForPeer({
      plaintextPayload: {
        text: secretPlaintext,
        timestamp: new Date().toISOString(),
      },
      conversationId,
      senderIdentity: aliceDevice,
      recipientX25519PublicKeyHex: bobDevice.x25519PublicKeyHex,
      sequenceNumber: 1,
      sessionEpoch: 1,
    });

    const { data: inserted, error: insertErr } = await aliceClient
      .from("encrypted_messages")
      .insert({
        conversation_id: conversationId,
        sender_id: aliceUserId,
        sender_device_id: aliceDevice.deviceId,
        recipient_id: bobUserId,
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        ephemeral_public_key: envelope.ephemeralPublicKey,
        sender_ed25519_public_key: envelope.senderEd25519PublicKey,
        sender_x25519_public_key: envelope.senderX25519PublicKey,
        signature: envelope.signature,
        sequence_number: envelope.sequenceNumber,
        session_epoch: envelope.sessionEpoch,
        algorithm: envelope.algorithm,
        message_type: "text",
        transport_mode: "store_and_forward",
      })
      .select("*")
      .single();

    expect(insertErr).toBeNull();
    expect(inserted).toBeTruthy();

    // Verify that the database record NEVER contains the plaintext string
    const serializedDbRecord = JSON.stringify(inserted);
    expect(serializedDbRecord).not.toContain(secretPlaintext);
    expect(serializedDbRecord).not.toContain("TOP_SECRET");

    // Bob fetches the encrypted message from the database and decrypts it locally
    const { data: bobMessages, error: bobFetchErr } = await bobClient
      .from("encrypted_messages")
      .select("*")
      .eq("conversation_id", conversationId);

    expect(bobFetchErr).toBeNull();
    expect(bobMessages).toHaveLength(1);

    const fetchedMsg = bobMessages![0];
    const decryptedByBob = decryptMessageEnvelope({
      envelope: {
        ciphertext: fetchedMsg.ciphertext,
        nonce: fetchedMsg.nonce,
        ephemeralPublicKey: fetchedMsg.ephemeral_public_key,
        senderEd25519PublicKey: fetchedMsg.sender_ed25519_public_key,
        senderX25519PublicKey: fetchedMsg.sender_x25519_public_key,
        signature: fetchedMsg.signature,
        sequenceNumber: Number(fetchedMsg.sequence_number),
        sessionEpoch: fetchedMsg.session_epoch,
        algorithm: fetchedMsg.algorithm,
      },
      conversationId,
      myX25519SecretKeyHex: bobDevice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: fetchedMsg.sender_x25519_public_key,
    });

    expect(decryptedByBob.text).toBe(secretPlaintext);
  }, 15000);

  it("enforces Row Level Security (RLS): blocks Mallory from reading or inserting into Alice & Bob's conversation", async () => {
    // 1. Mallory attempts to read Alice & Bob's encrypted messages
    const { data: malloryReadMsgs } = await malloryClient
      .from("encrypted_messages")
      .select("*")
      .eq("conversation_id", conversationId);

    expect(malloryReadMsgs ?? []).toHaveLength(0);

    // 2. Mallory attempts to read Alice & Bob's conversation metadata
    const { data: malloryReadConv } = await malloryClient
      .from("conversations")
      .select("*")
      .eq("id", conversationId);

    expect(malloryReadConv ?? []).toHaveLength(0);

    // 3. Mallory attempts to inject a message into Alice & Bob's conversation
    const fakeEnvelope = encryptMessageForPeer({
      plaintextPayload: {
        text: "Injected by Mallory",
        timestamp: new Date().toISOString(),
      },
      conversationId,
      senderIdentity: malloryDevice,
      recipientX25519PublicKeyHex: bobDevice.x25519PublicKeyHex,
      sequenceNumber: 99,
      sessionEpoch: 1,
    });

    const { error: malloryInsertErr } = await malloryClient
      .from("encrypted_messages")
      .insert({
        conversation_id: conversationId,
        sender_id: malloryUserId,
        ciphertext: fakeEnvelope.ciphertext,
        nonce: fakeEnvelope.nonce,
        ephemeral_public_key: fakeEnvelope.ephemeralPublicKey,
        sender_ed25519_public_key: fakeEnvelope.senderEd25519PublicKey,
        sender_x25519_public_key: fakeEnvelope.senderX25519PublicKey,
        signature: fakeEnvelope.signature,
        sequence_number: 99,
        session_epoch: 1,
      });

    expect(malloryInsertErr).not.toBeNull();

    // 4. Mallory attempts to revoke Alice's device
    const { data: updatedDevices } = await malloryClient
      .from("devices")
      .update({ is_revoked: true })
      .eq("id", aliceDevice.deviceId)
      .select("*");

    expect(updatedDevices ?? []).toHaveLength(0);
  }, 15000);

  it("verifies contact identity, rotates session keys, and revokes secondary devices", async () => {
    const safetyNumber = computeSafetyNumber(
      {
        userId: aliceUserId,
        ed25519PublicKeyHex: aliceDevice.ed25519PublicKeyHex,
        x25519PublicKeyHex: aliceDevice.x25519PublicKeyHex,
      },
      {
        userId: bobUserId,
        ed25519PublicKeyHex: bobDevice.ed25519PublicKeyHex,
        x25519PublicKeyHex: bobDevice.x25519PublicKeyHex,
      }
    );

    // Alice marks Bob's device as verified
    const { error: verifErr } = await aliceClient
      .from("contact_verifications")
      .insert({
        verifier_user_id: aliceUserId,
        contact_user_id: bobUserId,
        contact_device_id: bobDevice.deviceId,
        verified_fingerprint: bobDevice.fingerprint,
        safety_number: safetyNumber,
        verification_method: "manual",
        is_verified: true,
      });
    expect(verifErr).toBeNull();

    // Rotate session epoch to 2
    const { data: updatedConv, error: rotErr } = await aliceClient
      .from("conversations")
      .update({
        session_epoch: 2,
        last_key_rotation_at: new Date().toISOString(),
      })
      .eq("id", conversationId)
      .select("*")
      .single();

    expect(rotErr).toBeNull();
    expect(updatedConv?.session_epoch).toBe(2);

    // Alice registers a second temporary device and revokes it
    const tempDevice = generateDeviceIdentity("Alice Secondary Tablet", 1);
    await aliceClient.from("devices").insert({
      id: tempDevice.deviceId,
      user_id: aliceUserId,
      device_label: tempDevice.deviceLabel,
      ed25519_public_key: tempDevice.ed25519PublicKeyHex,
      x25519_public_key: tempDevice.x25519PublicKeyHex,
      fingerprint: tempDevice.fingerprint,
    });

    const { error: revokeErr } = await aliceClient
      .from("devices")
      .update({ is_revoked: true })
      .eq("id", tempDevice.deviceId);
    expect(revokeErr).toBeNull();

    const { data: checkRevoked } = await bobClient
      .from("devices")
      .select("is_revoked")
      .eq("id", tempDevice.deviceId)
      .single();
    expect(checkRevoked?.is_revoked).toBe(true);
  }, 15000);
});
