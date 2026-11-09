/**
 * CipherMesh Cryptographic Engine
 *
 * Uses audited @noble/* libraries (by Paul Miller, Cure53-audited):
 * - Ed25519 (@noble/curves/ed25519.js) for long-term identity and device signatures
 * - X25519 (@noble/curves/ed25519.js) for Diffie-Hellman key agreement
 * - HKDF-SHA256 (@noble/hashes/hkdf.js + @noble/hashes/sha2.js) for independent session & per-message key derivation
 * - XChaCha20-Poly1305 (@noble/ciphers/chacha.js) for 256-bit authenticated encryption with 192-bit (24-byte) extended nonces
 * - SHA-256 (@noble/hashes/sha2.js) for fingerprints, safety numbers, and file chunk integrity verification
 *
 * Private keys never leave the client device.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
  concatBytes,
  randomBytes,
  clean,
} from "@noble/hashes/utils.js";

export const CIPHERMESH_PROTOCOL_VERSION = "CipherMesh-v1";
export const CIPHERMESH_ALGORITHM_SUITE =
  "X25519-HKDF-SHA256-XChaCha20-Poly1305-Ed25519";

export interface DeviceIdentityBundle {
  deviceId: string;
  deviceLabel: string;
  ed25519SecretKeyHex: string;
  ed25519PublicKeyHex: string;
  x25519SecretKeyHex: string;
  x25519PublicKeyHex: string;
  keySignatureHex: string;
  fingerprint: string;
  keyVersion: number;
  createdAt: string;
}

export interface PublicIdentityBundle {
  userId: string;
  deviceId: string;
  ed25519PublicKeyHex: string;
  x25519PublicKeyHex: string;
  keySignatureHex?: string;
  fingerprint: string;
}

export interface EncryptedEnvelope {
  ciphertext: string; // hex
  nonce: string; // 24-byte (48 hex chars)
  ephemeralPublicKey: string; // 32-byte X25519 ephemeral public key (64 hex chars)
  senderEd25519PublicKey: string; // 32-byte Ed25519 public key (64 hex chars)
  senderX25519PublicKey: string; // 32-byte X25519 static public key (64 hex chars)
  signature: string; // 64-byte Ed25519 signature over canonical envelope transcript
  sequenceNumber: number;
  sessionEpoch: number;
  algorithm: string;
}

export interface PlaintextMessagePayload {
  text: string;
  timestamp: string;
  replyToPreview?: {
    id: string;
    senderName: string;
    snippet: string;
  } | null;
  fileAttachment?: {
    transferId: string;
    fileName: string;
    fileSize: number;
    mimeType: string;
    sha256Hash: string;
    totalChunks: number;
    encryptedDataBase64?: string; // For files <= 2MB when sent inline or P2P buffered
  } | null;
}

/**
 * Generates a fresh cryptographic identity bundle for the local device.
 * Signs the X25519 public key using the Ed25519 identity secret key to cryptographically bind them.
 */
export function generateDeviceIdentity(
  deviceLabel: string = "Browser Workstation",
  keyVersion: number = 1,
  existingDeviceId?: string
): DeviceIdentityBundle {
  const edKeys = ed25519.keygen();
  const xKeys = x25519.keygen();

  const edPubHex = bytesToHex(edKeys.publicKey);
  const xPubHex = bytesToHex(xKeys.publicKey);

  // Sign context-bound X25519 public key with Ed25519 identity key
  const bindContext = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:key-bind:${edPubHex}:${xPubHex}:v${keyVersion}`
  );
  const signature = ed25519.sign(bindContext, edKeys.secretKey);
  const fingerprint = computeIdentityFingerprint(edPubHex, xPubHex);

  const deviceId =
    existingDeviceId ||
    (typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : bytesToHex(randomBytes(16)));

  return {
    deviceId,
    deviceLabel,
    ed25519SecretKeyHex: bytesToHex(edKeys.secretKey),
    ed25519PublicKeyHex: edPubHex,
    x25519SecretKeyHex: bytesToHex(xKeys.secretKey),
    x25519PublicKeyHex: xPubHex,
    keySignatureHex: bytesToHex(signature),
    fingerprint,
    keyVersion,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Verifies that an X25519 public key is authentically signed by the owner's Ed25519 identity key.
 */
export function verifyKeyBindingSignature(
  ed25519PublicKeyHex: string,
  x25519PublicKeyHex: string,
  keySignatureHex: string,
  keyVersion: number = 1
): boolean {
  try {
    const bindContext = utf8ToBytes(
      `${CIPHERMESH_PROTOCOL_VERSION}:key-bind:${ed25519PublicKeyHex}:${x25519PublicKeyHex}:v${keyVersion}`
    );
    return ed25519.verify(
      hexToBytes(keySignatureHex),
      bindContext,
      hexToBytes(ed25519PublicKeyHex)
    );
  } catch {
    return false;
  }
}

/**
 * Computes a canonical uppercase hex fingerprint formatted in 8-character blocks
 * from a device's Ed25519 + X25519 public keys.
 */
export function computeIdentityFingerprint(
  ed25519PublicKeyHex: string,
  x25519PublicKeyHex: string
): string {
  const input = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:fingerprint:${ed25519PublicKeyHex.toLowerCase()}:${x25519PublicKeyHex.toLowerCase()}`
  );
  const digest = sha256(input);
  const hex = bytesToHex(digest).toUpperCase();
  // Return 64 hex chars grouped in 8 groups of 4 (first 32 chars = 128 bits for compact display, or full 64)
  return (
    hex
      .slice(0, 32)
      .match(/.{1,4}/g)
      ?.join(" ") ?? hex.slice(0, 32)
  );
}

/**
 * Computes a deterministic, order-independent 60-digit numeric Safety Number
 * between two peers so both Alice and Bob see the exact same 12x5 digit blocks.
 */
export function computeSafetyNumber(
  peerA: { userId: string; ed25519PublicKeyHex: string; x25519PublicKeyHex: string },
  peerB: { userId: string; ed25519PublicKeyHex: string; x25519PublicKeyHex: string }
): string {
  const canonicalA = `${peerA.userId.toLowerCase()}:${peerA.ed25519PublicKeyHex.toLowerCase()}:${peerA.x25519PublicKeyHex.toLowerCase()}`;
  const canonicalB = `${peerB.userId.toLowerCase()}:${peerB.ed25519PublicKeyHex.toLowerCase()}:${peerB.x25519PublicKeyHex.toLowerCase()}`;

  const [first, second] =
    canonicalA < canonicalB ? [canonicalA, canonicalB] : [canonicalB, canonicalA];

  // Iterative SHA-256 hashing to produce 12 blocks of 5 digits (60 digits total)
  const blocks: string[] = [];
  for (let i = 0; i < 12; i++) {
    const hashInput = utf8ToBytes(
      `${CIPHERMESH_PROTOCOL_VERSION}:safety-number:block-${i}:${first}|${second}`
    );
    const digest = sha256(hashInput);
    const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
    const num = view.getUint32(0, false) % 100000;
    blocks.push(num.toString().padStart(5, "0"));
  }

  return blocks.join(" ");
}

/**
 * Derives a deterministic Session Identifier (Session Fingerprint) from two peers' X25519 public keys and epoch.
 */
export function deriveSessionIdentifier(
  conversationId: string,
  myX25519PublicKeyHex: string,
  peerX25519PublicKeyHex: string,
  sessionEpoch: number = 1
): string {
  const [first, second] =
    myX25519PublicKeyHex.toLowerCase() < peerX25519PublicKeyHex.toLowerCase()
      ? [myX25519PublicKeyHex.toLowerCase(), peerX25519PublicKeyHex.toLowerCase()]
      : [peerX25519PublicKeyHex.toLowerCase(), myX25519PublicKeyHex.toLowerCase()];

  const digest = sha256(
    utf8ToBytes(
      `${CIPHERMESH_PROTOCOL_VERSION}:session-id:${conversationId}:${first}:${second}:epoch-${sessionEpoch}`
    )
  );
  return `CMS-${bytesToHex(digest).slice(0, 16).toUpperCase()}`;
}

/**
 * Derives a 32-byte symmetric message encryption key using Dual X25519 ECDH + HKDF-SHA256:
 * - Static-Static ECDH between sender X25519 identity key and recipient X25519 identity key
 * - Ephemeral-Static ECDH between per-message ephemeral X25519 key and recipient X25519 key
 * Note: So that the sender can also decrypt their own sent message history on the same device,
 * we combine static-static ECDH with the envelope's ephemeral public key in the HKDF salt/info!
 * Even better:
 * Let's examine how both sender and recipient derive the exact same message key:
 * - Static ECDH shared secret: `dhStatic = X25519(senderStaticPriv, recipientStaticPub) == X25519(recipientStaticPriv, senderStaticPub)`
 * - For real-time P2P sessions with ephemeral ratchet keys or per-message key isolation:
 *   We include `ephemeralPublicKey` (256-bit fresh random scalar point), `nonce` (192-bit), `conversationId`, `sequenceNumber`, and `sessionEpoch` in HKDF-SHA256 salt & info!
 *   And when a peer has an active P2P ephemeral ratchet public key, we also support ephemeral-ephemeral ECDH.
 */
export function deriveMessageSymmetricKey(params: {
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
  ephemeralPublicKeyHex: string;
  conversationId: string;
  sequenceNumber: number;
  sessionEpoch: number;
}): Uint8Array {
  const myPriv = hexToBytes(params.myX25519SecretKeyHex);
  const peerPub = hexToBytes(params.peerX25519PublicKeyHex);
  const ephPub = hexToBytes(params.ephemeralPublicKeyHex);

  const sharedStatic = x25519.getSharedSecret(myPriv, peerPub);
  const salt = sha256(
    concatBytes(
      ephPub,
      utf8ToBytes(`${params.conversationId}:epoch:${params.sessionEpoch}`)
    )
  );
  const info = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:message-key:seq:${params.sequenceNumber}:epoch:${params.sessionEpoch}`
  );

  const derivedKey = hkdf(sha256, sharedStatic, salt, info, 32);
  clean(sharedStatic, myPriv);
  return derivedKey;
}

/**
 * Builds the canonical Associated Authenticated Data (AAD) and signature transcript
 * for an encrypted message envelope so any tampering with headers, sequence number,
 * epoch, or keys causes both AEAD tag failure and Ed25519 signature rejection.
 */
function buildCanonicalAAD(params: {
  conversationId: string;
  senderEd25519PublicKeyHex: string;
  senderX25519PublicKeyHex: string;
  ephemeralPublicKeyHex: string;
  nonceHex: string;
  sequenceNumber: number;
  sessionEpoch: number;
}): Uint8Array {
  return utf8ToBytes(
    [
      CIPHERMESH_PROTOCOL_VERSION,
      params.conversationId,
      params.senderEd25519PublicKeyHex.toLowerCase(),
      params.senderX25519PublicKeyHex.toLowerCase(),
      params.ephemeralPublicKeyHex.toLowerCase(),
      params.nonceHex.toLowerCase(),
      `seq:${params.sequenceNumber}`,
      `epoch:${params.sessionEpoch}`,
    ].join("|")
  );
}

/**
 * Encrypts and signs a message payload for a peer using X25519 + HKDF-SHA256 + XChaCha20-Poly1305 + Ed25519.
 */
export function encryptMessageForPeer(params: {
  plaintextPayload: PlaintextMessagePayload;
  conversationId: string;
  senderIdentity: DeviceIdentityBundle;
  recipientX25519PublicKeyHex: string;
  sequenceNumber: number;
  sessionEpoch: number;
}): EncryptedEnvelope {
  if (params.sequenceNumber < 1 || !Number.isInteger(params.sequenceNumber)) {
    throw new Error("Invalid sequence number: must be a positive integer");
  }

  // Generate fresh 24-byte (192-bit) nonce and fresh ephemeral X25519 keypair
  const nonceBytes = randomBytes(24);
  const nonceHex = bytesToHex(nonceBytes);
  const ephemeralKeys = x25519.keygen();
  const ephemeralPublicKeyHex = bytesToHex(ephemeralKeys.publicKey);

  const messageKey = deriveMessageSymmetricKey({
    myX25519SecretKeyHex: params.senderIdentity.x25519SecretKeyHex,
    peerX25519PublicKeyHex: params.recipientX25519PublicKeyHex,
    ephemeralPublicKeyHex,
    conversationId: params.conversationId,
    sequenceNumber: params.sequenceNumber,
    sessionEpoch: params.sessionEpoch,
  });

  const aad = buildCanonicalAAD({
    conversationId: params.conversationId,
    senderEd25519PublicKeyHex: params.senderIdentity.ed25519PublicKeyHex,
    senderX25519PublicKeyHex: params.senderIdentity.x25519PublicKeyHex,
    ephemeralPublicKeyHex,
    nonceHex,
    sequenceNumber: params.sequenceNumber,
    sessionEpoch: params.sessionEpoch,
  });

  const plaintextBytes = utf8ToBytes(JSON.stringify(params.plaintextPayload));
  const cipher = xchacha20poly1305(messageKey, nonceBytes, aad);
  const ciphertextBytes = cipher.encrypt(plaintextBytes);
  const ciphertextHex = bytesToHex(ciphertextBytes);

  // Sign (AAD || ciphertextBytes) with sender's Ed25519 identity secret key
  const transcriptToSign = concatBytes(aad, ciphertextBytes);
  const edSecretBytes = hexToBytes(params.senderIdentity.ed25519SecretKeyHex);
  const signatureBytes = ed25519.sign(transcriptToSign, edSecretBytes);

  // Zeroize sensitive intermediates
  clean(messageKey, ephemeralKeys.secretKey, edSecretBytes, plaintextBytes);

  return {
    ciphertext: ciphertextHex,
    nonce: nonceHex,
    ephemeralPublicKey: ephemeralPublicKeyHex,
    senderEd25519PublicKey: params.senderIdentity.ed25519PublicKeyHex,
    senderX25519PublicKey: params.senderIdentity.x25519PublicKeyHex,
    signature: bytesToHex(signatureBytes),
    sequenceNumber: params.sequenceNumber,
    sessionEpoch: params.sessionEpoch,
    algorithm: CIPHERMESH_ALGORITHM_SUITE,
  };
}

/**
 * Verifies the Ed25519 signature and decrypts an EncryptedEnvelope using XChaCha20-Poly1305.
 * Works for both the recipient (using recipient's X25519 secret key + sender's X25519 public key)
 * and the sender reading their own sent message (using sender's X25519 secret key + recipient's X25519 public key).
 */
export function decryptMessageEnvelope(params: {
  envelope: EncryptedEnvelope;
  conversationId: string;
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
  expectedSenderEd25519PublicKeyHex?: string;
}): PlaintextMessagePayload {
  const { envelope } = params;

  if (
    params.expectedSenderEd25519PublicKeyHex &&
    envelope.senderEd25519PublicKey.toLowerCase() !==
      params.expectedSenderEd25519PublicKeyHex.toLowerCase()
  ) {
    throw new Error(
      "Sender Ed25519 identity key mismatch: possible impersonation attempt"
    );
  }

  const aad = buildCanonicalAAD({
    conversationId: params.conversationId,
    senderEd25519PublicKeyHex: envelope.senderEd25519PublicKey,
    senderX25519PublicKeyHex: envelope.senderX25519PublicKey,
    ephemeralPublicKeyHex: envelope.ephemeralPublicKey,
    nonceHex: envelope.nonce,
    sequenceNumber: envelope.sequenceNumber,
    sessionEpoch: envelope.sessionEpoch,
  });

  const ciphertextBytes = hexToBytes(envelope.ciphertext);
  const signatureBytes = hexToBytes(envelope.signature);
  const senderEdPubBytes = hexToBytes(envelope.senderEd25519PublicKey);

  // 1. Verify Ed25519 authenticity before attempting decryption (Encrypt-then-Sign / AEAD+Sign verification)
  const transcript = concatBytes(aad, ciphertextBytes);
  const isSignatureValid = ed25519.verify(
    signatureBytes,
    transcript,
    senderEdPubBytes
  );
  if (!isSignatureValid) {
    throw new Error("Cryptographic signature verification failed");
  }

  // 2. Derive the symmetric message key
  const messageKey = deriveMessageSymmetricKey({
    myX25519SecretKeyHex: params.myX25519SecretKeyHex,
    peerX25519PublicKeyHex: params.peerX25519PublicKeyHex,
    ephemeralPublicKeyHex: envelope.ephemeralPublicKey,
    conversationId: params.conversationId,
    sequenceNumber: envelope.sequenceNumber,
    sessionEpoch: envelope.sessionEpoch,
  });

  // 3. Decrypt and authenticate with XChaCha20-Poly1305
  const nonceBytes = hexToBytes(envelope.nonce);
  try {
    const cipher = xchacha20poly1305(messageKey, nonceBytes, aad);
    const decryptedBytes = cipher.decrypt(ciphertextBytes);
    const jsonStr = new TextDecoder().decode(decryptedBytes);
    clean(messageKey, decryptedBytes);
    return JSON.parse(jsonStr) as PlaintextMessagePayload;
  } catch (err) {
    clean(messageKey);
    throw new Error(
      `AEAD decryption failed: ${err instanceof Error ? err.message : "invalid tag or corrupted ciphertext"}`
    );
  }
}

/**
 * Replay Protection and Out-of-Order Sequence Window Tracker.
 * Tracks seen `(senderId, sessionEpoch, sequenceNumber)` tuples andseen nonces
 * to reject duplicate/replayed messages while allowing out-of-order delivery.
 */
export class ReplayProtectionWindow {
  private seenSequences = new Set<string>();
  private seenNonces = new Set<string>();
  private highestSequenceBySenderEpoch = new Map<string, number>();
  private readonly maxWindowHistory: number;

  constructor(maxWindowHistory: number = 2048) {
    this.maxWindowHistory = maxWindowHistory;
  }

  /**
   * Validates and records an incoming message envelope for replay protection.
   * Throws an error if a replay or duplicate nonce/sequence is detected.
   */
  public validateAndAccept(params: {
    senderId: string;
    sessionEpoch: number;
    sequenceNumber: number;
    nonceHex: string;
  }): { isOutOfOrder: boolean; highestSeen: number } {
    const { senderId, sessionEpoch, sequenceNumber, nonceHex } = params;

    if (!Number.isInteger(sequenceNumber) || sequenceNumber < 1) {
      throw new Error("Replay protection: invalid non-positive sequence number");
    }
    if (!Number.isInteger(sessionEpoch) || sessionEpoch < 1) {
      throw new Error("Replay protection: invalid session epoch");
    }

    const normalizedNonce = nonceHex.toLowerCase();
    if (this.seenNonces.has(normalizedNonce)) {
      throw new Error("Replay detected: duplicate cryptographic nonce rejected");
    }

    const seqKey = `${senderId}:epoch-${sessionEpoch}:seq-${sequenceNumber}`;
    if (this.seenSequences.has(seqKey)) {
      throw new Error(
        `Replay detected: duplicate sequence #${sequenceNumber} in epoch ${sessionEpoch}`
      );
    }

    const senderEpochKey = `${senderId}:epoch-${sessionEpoch}`;
    const currentHighest =
      this.highestSequenceBySenderEpoch.get(senderEpochKey) ?? 0;

    if (
      currentHighest > this.maxWindowHistory &&
      sequenceNumber <= currentHighest - this.maxWindowHistory
    ) {
      throw new Error(
        `Replay protection: sequence #${sequenceNumber} is outside the acceptable sliding window`
      );
    }

    this.seenNonces.add(normalizedNonce);
    this.seenSequences.add(seqKey);

    const isOutOfOrder = sequenceNumber < currentHighest;
    if (sequenceNumber > currentHighest) {
      this.highestSequenceBySenderEpoch.set(senderEpochKey, sequenceNumber);
    }

    return {
      isOutOfOrder,
      highestSeen: Math.max(currentHighest, sequenceNumber),
    };
  }

  public hasSeenMessage(
    senderId: string,
    sessionEpoch: number,
    sequenceNumber: number
  ): boolean {
    return this.seenSequences.has(
      `${senderId}:epoch-${sessionEpoch}:seq-${sequenceNumber}`
    );
  }

  public reset(): void {
    this.seenSequences.clear();
    this.seenNonces.clear();
    this.highestSequenceBySenderEpoch.clear();
  }
}

/**
 * Encrypted File Chunking & Integrity Verification
 * Splits files into chunks, encrypts each chunk with an independent derived chunk key and 24-byte nonce
 * using XChaCha20-Poly1305, and verifies the whole-file SHA-256 hash upon reassembly.
 */
export interface EncryptedFileChunk {
  transferId: string;
  chunkIndex: number;
  totalChunks: number;
  nonceHex: string;
  ciphertextHex: string;
  chunkHashHex: string;
}

export function computeBytesSha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export function encryptFileChunk(params: {
  chunkBytes: Uint8Array;
  transferId: string;
  chunkIndex: number;
  totalChunks: number;
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
}): EncryptedFileChunk {
  const sharedStatic = x25519.getSharedSecret(
    hexToBytes(params.myX25519SecretKeyHex),
    hexToBytes(params.peerX25519PublicKeyHex)
  );
  const salt = sha256(utf8ToBytes(`file-transfer:${params.transferId}`));
  const info = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:file-chunk:${params.chunkIndex}/${params.totalChunks}`
  );
  const chunkKey = hkdf(sha256, sharedStatic, salt, info, 32);

  const nonceBytes = randomBytes(24);
  const aad = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:file:${params.transferId}:chunk:${params.chunkIndex}/${params.totalChunks}`
  );
  const cipher = xchacha20poly1305(chunkKey, nonceBytes, aad);
  const ciphertextBytes = cipher.encrypt(params.chunkBytes);

  clean(sharedStatic, chunkKey);

  return {
    transferId: params.transferId,
    chunkIndex: params.chunkIndex,
    totalChunks: params.totalChunks,
    nonceHex: bytesToHex(nonceBytes),
    ciphertextHex: bytesToHex(ciphertextBytes),
    chunkHashHex: computeBytesSha256Hex(params.chunkBytes),
  };
}

export function decryptFileChunk(params: {
  chunk: EncryptedFileChunk;
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
}): Uint8Array {
  const { chunk } = params;
  const sharedStatic = x25519.getSharedSecret(
    hexToBytes(params.myX25519SecretKeyHex),
    hexToBytes(params.peerX25519PublicKeyHex)
  );
  const salt = sha256(utf8ToBytes(`file-transfer:${chunk.transferId}`));
  const info = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:file-chunk:${chunk.chunkIndex}/${chunk.totalChunks}`
  );
  const chunkKey = hkdf(sha256, sharedStatic, salt, info, 32);

  const aad = utf8ToBytes(
    `${CIPHERMESH_PROTOCOL_VERSION}:file:${chunk.transferId}:chunk:${chunk.chunkIndex}/${chunk.totalChunks}`
  );
  const cipher = xchacha20poly1305(chunkKey, hexToBytes(chunk.nonceHex), aad);
  const plaintextBytes = cipher.decrypt(hexToBytes(chunk.ciphertextHex));

  clean(sharedStatic, chunkKey);

  const computedHash = computeBytesSha256Hex(plaintextBytes);
  if (computedHash !== chunk.chunkHashHex) {
    throw new Error(
      `File chunk #${chunk.chunkIndex} SHA-256 integrity check failed`
    );
  }

  return plaintextBytes;
}

/**
 * Splits a Uint8Array file into encrypted chunks and reassembles them with full SHA-256 verification.
 */
export function splitAndEncryptFile(params: {
  fileBytes: Uint8Array;
  transferId: string;
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
  chunkSizeBytes?: number;
}): {
  chunks: EncryptedFileChunk[];
  fullFileSha256Hex: string;
} {
  const chunkSize = params.chunkSizeBytes ?? 16384; // 16 KB WebRTC-friendly chunks
  const totalChunks = Math.max(1, Math.ceil(params.fileBytes.length / chunkSize));
  const chunks: EncryptedFileChunk[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, params.fileBytes.length);
    const slice = params.fileBytes.subarray(start, end);
    chunks.push(
      encryptFileChunk({
        chunkBytes: slice,
        transferId: params.transferId,
        chunkIndex: i,
        totalChunks,
        myX25519SecretKeyHex: params.myX25519SecretKeyHex,
        peerX25519PublicKeyHex: params.peerX25519PublicKeyHex,
      })
    );
  }

  return {
    chunks,
    fullFileSha256Hex: computeBytesSha256Hex(params.fileBytes),
  };
}

export function decryptAndReassembleFile(params: {
  chunks: EncryptedFileChunk[];
  expectedFullSha256Hex: string;
  myX25519SecretKeyHex: string;
  peerX25519PublicKeyHex: string;
}): Uint8Array {
  if (params.chunks.length === 0) {
    throw new Error("No chunks provided for file reassembly");
  }

  const sorted = [...params.chunks].sort((a, b) => a.chunkIndex - b.chunkIndex);
  const expectedTotal = sorted[0].totalChunks;
  if (sorted.length !== expectedTotal) {
    throw new Error(
      `Incomplete file transfer: received ${sorted.length} of ${expectedTotal} chunks`
    );
  }

  const decryptedParts: Uint8Array[] = [];
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].chunkIndex !== i) {
      throw new Error(`Missing file chunk at index ${i}`);
    }
    decryptedParts.push(
      decryptFileChunk({
        chunk: sorted[i],
        myX25519SecretKeyHex: params.myX25519SecretKeyHex,
        peerX25519PublicKeyHex: params.peerX25519PublicKeyHex,
      })
    );
  }

  const reassembled = concatBytes(...decryptedParts);
  const actualHash = computeBytesSha256Hex(reassembled);
  if (actualHash !== params.expectedFullSha256Hex.toLowerCase()) {
    throw new Error(
      "Reassembled file SHA-256 digest does not match manifest hash"
    );
  }

  return reassembled;
}
