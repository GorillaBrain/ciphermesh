import { describe, it, expect } from "vitest";
import {
  generateDeviceIdentity,
  verifyKeyBindingSignature,
  computeIdentityFingerprint,
  computeSafetyNumber,
  deriveSessionIdentifier,
  deriveMessageSymmetricKey,
  encryptMessageForPeer,
  decryptMessageEnvelope,
  ReplayProtectionWindow,
  splitAndEncryptFile,
  decryptAndReassembleFile,
  CIPHERMESH_ALGORITHM_SUITE,
} from "../crypto/engine";

describe("CipherMesh Cryptographic Engine", () => {
  it("generates valid Ed25519 + X25519 device identities and verifies key-binding signatures", () => {
    const alice = generateDeviceIdentity("Alice Workstation", 1);
    const bob = generateDeviceIdentity("Bob Laptop", 1);

    expect(alice.ed25519PublicKeyHex).toHaveLength(64);
    expect(alice.ed25519SecretKeyHex).toHaveLength(64);
    expect(alice.x25519PublicKeyHex).toHaveLength(64);
    expect(alice.x25519SecretKeyHex).toHaveLength(64);
    expect(alice.keySignatureHex).toHaveLength(128);

    // Valid signature passes
    expect(
      verifyKeyBindingSignature(
        alice.ed25519PublicKeyHex,
        alice.x25519PublicKeyHex,
        alice.keySignatureHex,
        1
      )
    ).toBe(true);

    // Cross-key substitution fails
    expect(
      verifyKeyBindingSignature(
        alice.ed25519PublicKeyHex,
        bob.x25519PublicKeyHex,
        alice.keySignatureHex,
        1
      )
    ).toBe(false);

    // Version mismatch fails
    expect(
      verifyKeyBindingSignature(
        alice.ed25519PublicKeyHex,
        alice.x25519PublicKeyHex,
        alice.keySignatureHex,
        2
      )
    ).toBe(false);
  });

  it("computes deterministic, order-independent 60-digit safety numbers and session identifiers", () => {
    const alice = generateDeviceIdentity("Alice", 1);
    const bob = generateDeviceIdentity("Bob", 1);

    const peerA = {
      userId: "user-alice-uuid",
      ed25519PublicKeyHex: alice.ed25519PublicKeyHex,
      x25519PublicKeyHex: alice.x25519PublicKeyHex,
    };
    const peerB = {
      userId: "user-bob-uuid",
      ed25519PublicKeyHex: bob.ed25519PublicKeyHex,
      x25519PublicKeyHex: bob.x25519PublicKeyHex,
    };

    const safetyAB = computeSafetyNumber(peerA, peerB);
    const safetyBA = computeSafetyNumber(peerB, peerA);

    expect(safetyAB).toBe(safetyBA);
    // 12 blocks of 5 digits separated by spaces = 71 chars
    expect(safetyAB.split(" ")).toHaveLength(12);
    for (const block of safetyAB.split(" ")) {
      expect(block).toMatch(/^\d{5}$/);
    }

    const sessionAB = deriveSessionIdentifier(
      "conv-123",
      alice.x25519PublicKeyHex,
      bob.x25519PublicKeyHex,
      1
    );
    const sessionBA = deriveSessionIdentifier(
      "conv-123",
      bob.x25519PublicKeyHex,
      alice.x25519PublicKeyHex,
      1
    );
    expect(sessionAB).toBe(sessionBA);
    expect(sessionAB).toMatch(/^CMS-[0-9A-F]{16}$/);

    // Rotating session epoch changes session identifier
    const sessionEpoch2 = deriveSessionIdentifier(
      "conv-123",
      alice.x25519PublicKeyHex,
      bob.x25519PublicKeyHex,
      2
    );
    expect(sessionEpoch2).not.toBe(sessionAB);
  });

  it("derives identical HKDF-SHA256 symmetric message keys for sender and recipient", () => {
    const alice = generateDeviceIdentity("Alice", 1);
    const bob = generateDeviceIdentity("Bob", 1);
    const ephemeral = generateDeviceIdentity("Ephemeral", 1);

    const keyAlice = deriveMessageSymmetricKey({
      myX25519SecretKeyHex: alice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: bob.x25519PublicKeyHex,
      ephemeralPublicKeyHex: ephemeral.x25519PublicKeyHex,
      conversationId: "conv-abc",
      sequenceNumber: 1,
      sessionEpoch: 1,
    });

    const keyBob = deriveMessageSymmetricKey({
      myX25519SecretKeyHex: bob.x25519SecretKeyHex,
      peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      ephemeralPublicKeyHex: ephemeral.x25519PublicKeyHex,
      conversationId: "conv-abc",
      sequenceNumber: 1,
      sessionEpoch: 1,
    });

    expect(Buffer.from(keyAlice).toString("hex")).toBe(
      Buffer.from(keyBob).toString("hex")
    );

    // Different sequence number yields completely independent key
    const keySeq2 = deriveMessageSymmetricKey({
      myX25519SecretKeyHex: alice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: bob.x25519PublicKeyHex,
      ephemeralPublicKeyHex: ephemeral.x25519PublicKeyHex,
      conversationId: "conv-abc",
      sequenceNumber: 2,
      sessionEpoch: 1,
    });
    expect(Buffer.from(keySeq2).toString("hex")).not.toBe(
      Buffer.from(keyAlice).toString("hex")
    );
  });

  it("encrypts and decrypts messages with XChaCha20-Poly1305 and Ed25519 authenticity", () => {
    const alice = generateDeviceIdentity("Alice", 1);
    const bob = generateDeviceIdentity("Bob", 1);
    const convId = "conv-e2ee-test";

    const payload = {
      text: "Zero-knowledge architectural test payload #42",
      timestamp: new Date().toISOString(),
      replyToPreview: null,
      fileAttachment: null,
    };

    const envelope = encryptMessageForPeer({
      plaintextPayload: payload,
      conversationId: convId,
      senderIdentity: alice,
      recipientX25519PublicKeyHex: bob.x25519PublicKeyHex,
      sequenceNumber: 1,
      sessionEpoch: 1,
    });

    expect(envelope.algorithm).toBe(CIPHERMESH_ALGORITHM_SUITE);
    expect(envelope.nonce).toHaveLength(48); // 24 bytes = 48 hex chars
    expect(envelope.ciphertext).not.toContain("Zero-knowledge");

    // Recipient (Bob) decrypts using Bob's secret key + Alice's public key
    const decryptedByBob = decryptMessageEnvelope({
      envelope,
      conversationId: convId,
      myX25519SecretKeyHex: bob.x25519SecretKeyHex,
      peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      expectedSenderEd25519PublicKeyHex: alice.ed25519PublicKeyHex,
    });
    expect(decryptedByBob.text).toBe(payload.text);

    // Sender (Alice) can also decrypt her own sent message in history using Alice's secret key + Bob's public key
    const decryptedByAlice = decryptMessageEnvelope({
      envelope,
      conversationId: convId,
      myX25519SecretKeyHex: alice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: bob.x25519PublicKeyHex,
      expectedSenderEd25519PublicKeyHex: alice.ed25519PublicKeyHex,
    });
    expect(decryptedByAlice.text).toBe(payload.text);
  });

  it("rejects tampered ciphertext, modified sequence numbers, or forged sender signatures", () => {
    const alice = generateDeviceIdentity("Alice", 1);
    const bob = generateDeviceIdentity("Bob", 1);
    const mallory = generateDeviceIdentity("Mallory", 1);
    const convId = "conv-tamper-test";

    const envelope = encryptMessageForPeer({
      plaintextPayload: {
        text: "Confidential transfer instructions",
        timestamp: new Date().toISOString(),
      },
      conversationId: convId,
      senderIdentity: alice,
      recipientX25519PublicKeyHex: bob.x25519PublicKeyHex,
      sequenceNumber: 7,
      sessionEpoch: 2,
    });

    // 1. Tamper with 1 byte of ciphertext
    const flippedByte =
      envelope.ciphertext.slice(0, 2) === "ff" ? "00" : "ff";
    const tamperedCiphertextEnvelope = {
      ...envelope,
      ciphertext: flippedByte + envelope.ciphertext.slice(2),
    };

    expect(() =>
      decryptMessageEnvelope({
        envelope: tamperedCiphertextEnvelope,
        conversationId: convId,
        myX25519SecretKeyHex: bob.x25519SecretKeyHex,
        peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      })
    ).toThrow(/signature verification failed/i);

    // 2. Tamper with sequence number in envelope metadata
    const tamperedSequenceEnvelope = {
      ...envelope,
      sequenceNumber: 8,
    };

    expect(() =>
      decryptMessageEnvelope({
        envelope: tamperedSequenceEnvelope,
        conversationId: convId,
        myX25519SecretKeyHex: bob.x25519SecretKeyHex,
        peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      })
    ).toThrow(/signature verification failed/i);

    // 3. Unauthorized third-party (Mallory) cannot decrypt
    expect(() =>
      decryptMessageEnvelope({
        envelope,
        conversationId: convId,
        myX25519SecretKeyHex: mallory.x25519SecretKeyHex,
        peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      })
    ).toThrow(/AEAD decryption failed/i);
  });

  it("enforces replay protection and handles out-of-order sequences safely", () => {
    const window = new ReplayProtectionWindow(100);

    // Accept sequence 1
    const res1 = window.validateAndAccept({
      senderId: "alice",
      sessionEpoch: 1,
      sequenceNumber: 1,
      nonceHex: "aa".repeat(24),
    });
    expect(res1.isOutOfOrder).toBe(false);

    // Accept sequence 3 (sequence 2 delayed)
    const res3 = window.validateAndAccept({
      senderId: "alice",
      sessionEpoch: 1,
      sequenceNumber: 3,
      nonceHex: "cc".repeat(24),
    });
    expect(res3.isOutOfOrder).toBe(false);

    // Accept delayed sequence 2 (out-of-order)
    const res2 = window.validateAndAccept({
      senderId: "alice",
      sessionEpoch: 1,
      sequenceNumber: 2,
      nonceHex: "bb".repeat(24),
    });
    expect(res2.isOutOfOrder).toBe(true);

    // Reject duplicate sequence 2
    expect(() =>
      window.validateAndAccept({
        senderId: "alice",
        sessionEpoch: 1,
        sequenceNumber: 2,
        nonceHex: "dd".repeat(24),
      })
    ).toThrow(/Replay detected: duplicate sequence/i);

    // Reject duplicate nonce even with new sequence number
    expect(() =>
      window.validateAndAccept({
        senderId: "alice",
        sessionEpoch: 1,
        sequenceNumber: 4,
        nonceHex: "aa".repeat(24),
      })
    ).toThrow(/Replay detected: duplicate cryptographic nonce/i);
  });

  it("splits, encrypts, verifies, and reassembles multi-chunk files with SHA-256 integrity", () => {
    const alice = generateDeviceIdentity("Alice", 1);
    const bob = generateDeviceIdentity("Bob", 1);

    // Create a 40 KB synthetic file payload
    const originalBytes = new Uint8Array(40000);
    for (let i = 0; i < originalBytes.length; i++) {
      originalBytes[i] = (i * 31 + 7) & 0xff;
    }

    const { chunks, fullFileSha256Hex } = splitAndEncryptFile({
      fileBytes: originalBytes,
      transferId: "transfer-001",
      myX25519SecretKeyHex: alice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: bob.x25519PublicKeyHex,
      chunkSizeBytes: 16384,
    });

    expect(chunks).toHaveLength(3);

    // Shuffle chunks to verify out-of-order chunk reassembly
    const shuffled = [chunks[2], chunks[0], chunks[1]];

    const reassembled = decryptAndReassembleFile({
      chunks: shuffled,
      expectedFullSha256Hex: fullFileSha256Hex,
      myX25519SecretKeyHex: bob.x25519SecretKeyHex,
      peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
    });

    expect(reassembled.length).toBe(originalBytes.length);
    expect(Buffer.from(reassembled).equals(Buffer.from(originalBytes))).toBe(
      true
    );

    // Tampering with expected manifest hash fails verification
    expect(() =>
      decryptAndReassembleFile({
        chunks,
        expectedFullSha256Hex: "00".repeat(32),
        myX25519SecretKeyHex: bob.x25519SecretKeyHex,
        peerX25519PublicKeyHex: alice.x25519PublicKeyHex,
      })
    ).toThrow(/SHA-256 digest does not match/i);
  });
});
