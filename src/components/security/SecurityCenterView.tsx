"use client";

import React, { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Cpu,
  Radio,
  RefreshCw,
  QrCode,
  Check,
  Copy,
  Trash2,
  AlertTriangle,
  Key,
  Terminal,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
} from "lucide-react";
import type {
  DeviceRecord,
  SecurityEventRecord,
  ContactVerificationRecord,
  UserProfile,
} from "@/types/ciphermesh";
import type { DeviceIdentityBundle } from "@/lib/crypto/engine";
import {
  CIPHERMESH_ALGORITHM_SUITE,
  computeSafetyNumber,
  deriveSessionIdentifier,
} from "@/lib/crypto/engine";
import type { WebRTCConnectionTelemetry } from "@/lib/webrtc/peer-manager";

interface SecurityCenterViewProps {
  currentUser: UserProfile;
  localDevice: DeviceIdentityBundle | null;
  myDevices: DeviceRecord[];
  peerProfile: UserProfile | null;
  peerActiveDevice: DeviceRecord | null;
  activeConversationId: string | null;
  sessionEpoch: number;
  lastKeyRotationAt: string | null;
  telemetry: WebRTCConnectionTelemetry | null;
  verifications: ContactVerificationRecord[];
  securityEvents: SecurityEventRecord[];
  identityChangedPeers: Record<string, string>; // userId -> previousFingerprint
  onVerifyPeer: (
    peerId: string,
    peerDeviceId: string | null,
    fingerprint: string,
    safetyNumber: string,
    method: "manual" | "qr_scan"
  ) => Promise<void>;
  onRevokeDevice: (deviceId: string, fingerprint: string) => Promise<void>;
  onRotateSessionKeys: () => Promise<void>;
  onRotateDeviceIdentityKeys: () => Promise<void>;
  onTerminateSession: () => Promise<void>;
}

export function SecurityCenterView({
  currentUser,
  localDevice,
  myDevices,
  peerProfile,
  peerActiveDevice,
  activeConversationId,
  sessionEpoch,
  lastKeyRotationAt,
  telemetry,
  verifications,
  securityEvents,
  identityChangedPeers,
  onVerifyPeer,
  onRevokeDevice,
  onRotateSessionKeys,
  onRotateDeviceIdentityKeys,
  onTerminateSession,
}: SecurityCenterViewProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [qrInputPayload, setQrInputPayload] = useState("");
  const [qrScanFeedback, setQrScanFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [rotatingKeys, setRotatingKeys] = useState(false);

  const activeSessionId =
    activeConversationId && localDevice && peerActiveDevice
      ? deriveSessionIdentifier(
          activeConversationId,
          localDevice.x25519PublicKeyHex,
          peerActiveDevice.x25519_public_key,
          sessionEpoch
        )
      : localDevice
        ? `CMS-LOCAL-${localDevice.fingerprint.replace(/\s+/g, "").slice(0, 12)}`
        : "UNINITIALIZED";

  const activeSafetyNumber =
    localDevice && peerProfile && peerActiveDevice
      ? computeSafetyNumber(
          {
            userId: currentUser.id,
            ed25519PublicKeyHex: localDevice.ed25519PublicKeyHex,
            x25519PublicKeyHex: localDevice.x25519PublicKeyHex,
          },
          {
            userId: peerProfile.id,
            ed25519PublicKeyHex: peerActiveDevice.ed25519_public_key,
            x25519PublicKeyHex: peerActiveDevice.x25519_public_key,
          }
        )
      : null;

  const isPeerVerified = Boolean(
    peerProfile &&
      peerActiveDevice &&
      verifications.some(
        (v) =>
          v.contact_user_id === peerProfile.id &&
          v.verified_fingerprint === peerActiveDevice.fingerprint &&
          v.is_verified
      )
  );

  const myQrIdentityPayload = localDevice
    ? JSON.stringify({
        p: "CipherMesh-v1",
        uid: currentUser.id,
        u: currentUser.username,
        fp: localDevice.fingerprint,
        ed: localDevice.ed25519PublicKeyHex,
        x: localDevice.x25519PublicKeyHex,
      })
    : "";

  function copyToClipboard(text: string, label: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      void navigator.clipboard.writeText(text);
      setCopiedField(label);
      setTimeout(() => setCopiedField(null), 2000);
    }
  }

  async function handleQrComparisonVerify(e: React.FormEvent) {
    e.preventDefault();
    setQrScanFeedback(null);
    if (!peerProfile || !peerActiveDevice || !activeSafetyNumber) {
      setQrScanFeedback({
        type: "error",
        message: "Select an active contact conversation to verify QR payload.",
      });
      return;
    }

    try {
      const trimmed = qrInputPayload.trim();
      // Accept either JSON QR payload or raw fingerprint string
      let matches = false;
      if (trimmed.startsWith("{")) {
        const parsed = JSON.parse(trimmed);
        matches =
          parsed.fp === peerActiveDevice.fingerprint &&
          parsed.ed?.toLowerCase() ===
            peerActiveDevice.ed25519_public_key.toLowerCase();
      } else {
        matches =
          trimmed.replace(/\s+/g, "").toUpperCase() ===
          peerActiveDevice.fingerprint.replace(/\s+/g, "").toUpperCase();
      }

      if (!matches) {
        setQrScanFeedback({
          type: "error",
          message:
            "Cryptographic mismatch! The provided QR identity payload does NOT match this contact's public key fingerprint.",
        });
        return;
      }

      await onVerifyPeer(
        peerProfile.id,
        peerActiveDevice.id,
        peerActiveDevice.fingerprint,
        activeSafetyNumber,
        "qr_scan"
      );
      setQrScanFeedback({
        type: "success",
        message: `QR Identity verified for @${peerProfile.username} (${peerActiveDevice.fingerprint}).`,
      });
      setQrInputPayload("");
    } catch {
      setQrScanFeedback({
        type: "error",
        message: "Invalid QR payload format.",
      });
    }
  }

  return (
    <div className="flex-1 overflow-y-auto bg-[#090a0f] p-4 sm:p-6 lg:p-8">
      <div className="mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 border-b border-white/[0.075] pb-5 sm:flex-row sm:items-center">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs text-violet-400">
              <Terminal className="h-3.5 w-3.5" />
              <span>CRYPTOGRAPHIC POSTURE & AUDIT TELEMETRY</span>
            </div>
            <h1 className="mt-1 text-xl font-semibold tracking-tight text-white sm:text-2xl">
              CipherMesh Security Center
            </h1>
            <p className="mt-1 text-xs text-zinc-400">
              Live inspection of application-layer E2EE parameters, device trust
              records, WebRTC candidate topology, and security events.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {activeConversationId && (
              <>
                <button
                  type="button"
                  disabled={rotatingKeys}
                  onClick={async () => {
                    setRotatingKeys(true);
                    await onRotateSessionKeys();
                    setRotatingKeys(false);
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 px-3 py-2 text-xs font-medium text-violet-300 transition-colors hover:bg-violet-500/20 disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${rotatingKeys ? "animate-spin" : ""}`}
                  />
                  <span>Rotate Session Keys</span>
                </button>
                <button
                  type="button"
                  onClick={() => void onTerminateSession()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20"
                >
                  <XCircle className="h-3.5 w-3.5" />
                  <span>Terminate Session</span>
                </button>
              </>
            )}
            <button
              type="button"
              disabled={rotatingKeys}
              onClick={async () => {
                setRotatingKeys(true);
                await onRotateDeviceIdentityKeys();
                setRotatingKeys(false);
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-white/12 bg-[#11131a] px-3 py-2 text-xs font-medium text-zinc-200 transition-colors hover:border-white/25 hover:bg-[#171a24] disabled:opacity-50"
            >
              <Key className="h-3.5 w-3.5 text-sky-400" />
              <span>Rotate Local Device Keypair</span>
            </button>
          </div>
        </div>

        {/* Unexpected Identity Change Warning Banner */}
        {peerProfile && identityChangedPeers[peerProfile.id] && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-xs text-amber-200"
          >
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            <div>
              <div className="font-semibold text-amber-300">
                WARNING: Verified Contact Identity Key Changed (@
                {peerProfile.username})
              </div>
              <p className="mt-1 leading-relaxed">
                This contact previously had verified fingerprint{" "}
                <span className="font-mono">
                  {identityChangedPeers[peerProfile.id]}
                </span>
                , which has changed to{" "}
                <span className="font-mono">
                  {peerActiveDevice?.fingerprint}
                </span>
                . This may indicate the contact registered a new device or
                rotated keys, or it could indicate an active interception
                attempt. Re-verify safety numbers out-of-band before sending
                sensitive information.
              </p>
            </div>
          </div>
        )}

        {/* Section A & C: Encryption Status + Connection Security Topology */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* A. Encryption Status */}
          <section
            aria-label="Encryption Status"
            className="rounded-xl border border-white/10 bg-[#11131a] p-5 lg:col-span-7"
          >
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-violet-400" />
                <h2 className="text-sm font-semibold text-white">
                  A. Encryption Status & Session Parameters
                </h2>
              </div>
              <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                PRIVATE KEYS: CLIENT-BOUND
              </span>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3.5 sm:grid-cols-2">
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="font-mono text-[10px] text-zinc-500">
                  CIPHER SUITE ALGORITHM
                </div>
                <div className="mt-1 font-mono text-xs font-medium text-violet-300 break-all">
                  {CIPHERMESH_ALGORITHM_SUITE}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="font-mono text-[10px] text-zinc-500">
                  ACTIVE SESSION IDENTIFIER
                </div>
                <div className="mt-1 flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-medium text-white">
                    {activeSessionId}
                  </span>
                  <span className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                    EPOCH {sessionEpoch}
                  </span>
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3 sm:col-span-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] text-zinc-500">
                    LOCAL DEVICE PUBLIC KEY FINGERPRINT (SHA-256)
                  </span>
                  {localDevice && (
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(localDevice.fingerprint, "local-fp")
                      }
                      className="inline-flex items-center gap-1 font-mono text-[10px] text-violet-400 hover:text-violet-300"
                    >
                      {copiedField === "local-fp" ? (
                        <>
                          <Check className="h-3 w-3" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copy Fingerprint</span>
                        </>
                      )}
                    </button>
                  )}
                </div>
                <div className="mt-1.5 font-mono text-xs tracking-wider text-emerald-400">
                  {localDevice?.fingerprint ?? "Generating..."}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="font-mono text-[10px] text-zinc-500">
                  SESSION / KEY CREATION TIME
                </div>
                <div className="mt-1 font-mono text-xs text-zinc-300">
                  {localDevice
                    ? new Date(localDevice.createdAt).toLocaleString()
                    : "—"}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="font-mono text-[10px] text-zinc-500">
                  LAST KEY ROTATION
                </div>
                <div className="mt-1 font-mono text-xs text-zinc-300">
                  {lastKeyRotationAt
                    ? new Date(lastKeyRotationAt).toLocaleString()
                    : localDevice
                      ? `v${localDevice.keyVersion} (${new Date(localDevice.createdAt).toLocaleTimeString()})`
                      : "—"}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3 sm:col-span-2">
                <div className="font-mono text-[10px] text-zinc-500">
                  PEER AUTHENTICATION & VERIFICATION POSTURE
                </div>
                <div className="mt-1.5 flex flex-wrap items-center justify-between gap-2">
                  {peerProfile ? (
                    isPeerVerified ? (
                      <div className="flex items-center gap-2 text-xs font-medium text-emerald-400">
                        <ShieldCheck className="h-4 w-4" />
                        <span>
                          Cryptographically Verified Identity (@
                          {peerProfile.username})
                        </span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-xs font-medium text-amber-400">
                        <ShieldAlert className="h-4 w-4" />
                        <span>
                          Connected (Unverified Identity — Compare Safety Number
                          Below)
                        </span>
                      </div>
                    )
                  ) : (
                    <div className="text-xs text-zinc-400">
                      Local Node Authenticated (@{currentUser.username}) —
                      Select a conversation to inspect peer verification state.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </section>

          {/* C. Connection Security & Topology Visualization */}
          <section
            aria-label="Connection Security"
            className="rounded-xl border border-white/10 bg-[#11131a] p-5 lg:col-span-5"
          >
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <Radio className="h-4 w-4 text-sky-400" />
                <h2 className="text-sm font-semibold text-white">
                  C. Connection Security & Topology
                </h2>
              </div>
              <span
                className={`rounded border px-2 py-0.5 font-mono text-[10px] ${
                  telemetry?.topology === "direct_p2p"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    : telemetry?.topology === "turn_relay"
                      ? "border-sky-500/30 bg-sky-500/10 text-sky-300"
                      : "border-zinc-500/30 bg-white/[0.04] text-zinc-300"
                }`}
              >
                {telemetry?.topology === "direct_p2p"
                  ? "DIRECT P2P DATACHANNEL"
                  : telemetry?.topology === "turn_relay"
                    ? "TURN RELAYED P2P"
                    : "ENCRYPTED STORE & FORWARD"}
              </span>
            </div>

            {/* Topology Visualization */}
            <div className="mt-4 rounded-lg border border-white/[0.06] bg-[#090a0f] p-4">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <div className="text-center">
                  <div className="rounded border border-violet-500/40 bg-violet-500/10 px-2.5 py-1.5 text-violet-300">
                    @{currentUser.username}
                  </div>
                  <div className="mt-1 text-[10px] text-zinc-500">
                    {telemetry?.localCandidateType ?? "local"}
                  </div>
                </div>

                <div className="flex flex-1 flex-col items-center px-3">
                  <div className="text-[10px] text-sky-400">
                    {telemetry?.topology === "direct_p2p"
                      ? "Direct ICE Path"
                      : telemetry?.topology === "turn_relay"
                        ? "TURN Relay Hop"
                        : "Encrypted Envelope Sync"}
                  </div>
                  <div className="my-1.5 h-[1px] w-full bg-white/15" />
                  <div className="text-[10px] text-emerald-400">
                    XChaCha20-Poly1305
                  </div>
                </div>

                <div className="text-center">
                  <div className="rounded border border-sky-500/40 bg-sky-500/10 px-2.5 py-1.5 text-sky-300">
                    {peerProfile ? `@${peerProfile.username}` : "Peer Node"}
                  </div>
                  <div className="mt-1 text-[10px] text-zinc-500">
                    {telemetry?.remoteCandidateType ?? "remote"}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-3.5 space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] px-3 py-2">
                <span className="text-zinc-500">ICE STATE:</span>
                <span className="text-zinc-200">
                  {telemetry?.iceConnectionState ?? "standby"}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] px-3 py-2">
                <span className="text-zinc-500">DATACHANNEL STATE:</span>
                <span className="text-zinc-200">
                  {telemetry?.dataChannelState ?? "standby"}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] px-3 py-2">
                <span className="text-zinc-500">TRANSPORT SECURITY:</span>
                <span className="text-emerald-400">
                  App-Layer AEAD + DTLS 1.3
                </span>
              </div>
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] px-3 py-2">
                <div className="text-[10px] text-zinc-500">
                  LAST CONNECTION EVENT:
                </div>
                <div className="mt-0.5 text-[11px] text-zinc-300">
                  {telemetry?.lastEvent ??
                    "Encrypted store-and-forward channel active; open a conversation to negotiate P2P DataChannel."}
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* Contact Identity Verification & QR Comparison Workflow */}
        <section
          aria-label="Identity Verification Workflow"
          className="rounded-xl border border-white/10 bg-[#11131a] p-5"
        >
          <div className="flex flex-col justify-between gap-2 border-b border-white/[0.075] pb-3.5 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2">
              <QrCode className="h-4 w-4 text-violet-400" />
              <h2 className="text-sm font-semibold text-white">
                Cryptographic Identity Verification & QR Safety Number Inspector
              </h2>
            </div>
            <span className="font-mono text-xs text-zinc-400">
              Connected ≠ Verified — Compare 60-Digit Safety Numbers Out-of-Band
            </span>
          </div>

          <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Local QR Code */}
            <div className="flex flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-[#090a0f] p-5 lg:col-span-4">
              <div className="mb-3 font-mono text-xs font-medium text-zinc-300">
                YOUR IDENTITY QR (@{currentUser.username})
              </div>
              {myQrIdentityPayload && (
                <div className="rounded-xl border border-white/10 bg-white p-3">
                  <QRCodeSVG
                    value={myQrIdentityPayload}
                    size={148}
                    level="M"
                    includeMargin={false}
                  />
                </div>
              )}
              <button
                type="button"
                onClick={() =>
                  copyToClipboard(myQrIdentityPayload, "my-qr-json")
                }
                className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 font-mono text-[11px] text-zinc-300 hover:border-white/25"
              >
                {copiedField === "my-qr-json" ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span>Copied QR Identity Payload</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy My QR Payload</span>
                  </>
                )}
              </button>
            </div>

            {/* Active Peer Safety Number & Verification Controls */}
            <div className="flex flex-col justify-between space-y-4 lg:col-span-8">
              {peerProfile && peerActiveDevice && activeSafetyNumber ? (
                <>
                  <div className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <span className="font-mono text-xs text-zinc-400">
                          PEER NODE:{" "}
                        </span>
                        <span className="text-sm font-semibold text-white">
                          {peerProfile.display_name} (@{peerProfile.username})
                        </span>
                      </div>
                      <span
                        className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[11px] ${
                          isPeerVerified
                            ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                            : "border border-amber-500/30 bg-amber-500/10 text-amber-300"
                        }`}
                      >
                        {isPeerVerified ? (
                          <>
                            <ShieldCheck className="h-3.5 w-3.5" />
                            <span>VERIFIED IDENTITY</span>
                          </>
                        ) : (
                          <>
                            <ShieldAlert className="h-3.5 w-3.5" />
                            <span>UNVERIFIED IDENTITY</span>
                          </>
                        )}
                      </span>
                    </div>

                    <div className="mt-3">
                      <div className="font-mono text-[10px] text-zinc-500">
                        PEER PUBLIC IDENTITY FINGERPRINT
                      </div>
                      <div className="mt-1 font-mono text-xs text-sky-400">
                        {peerActiveDevice.fingerprint}
                      </div>
                    </div>

                    <div className="mt-3">
                      <div className="font-mono text-[10px] text-zinc-500">
                        60-DIGIT SAFETY NUMBER (DETERMINISTIC SHA-256 PAIR
                        DIGEST)
                      </div>
                      <div className="mt-1.5 grid grid-cols-3 gap-2 rounded-lg border border-white/[0.06] bg-[#11131a] p-3 font-mono text-xs tracking-widest text-emerald-300 sm:grid-cols-6">
                        {activeSafetyNumber.split(" ").map((block, idx) => (
                          <span key={idx} className="text-center">
                            {block}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="mt-4 flex flex-wrap items-center gap-3">
                      <button
                        type="button"
                        onClick={() =>
                          void onVerifyPeer(
                            peerProfile.id,
                            peerActiveDevice.id,
                            peerActiveDevice.fingerprint,
                            activeSafetyNumber,
                            "manual"
                          )
                        }
                        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-emerald-500"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span>
                          {isPeerVerified
                            ? "Re-Confirm Manual Verification"
                            : "Mark Contact as Verified"}
                        </span>
                      </button>
                    </div>
                  </div>

                  {/* QR Payload Scanner / Verifier */}
                  <form
                    onSubmit={handleQrComparisonVerify}
                    className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4"
                  >
                    <label
                      htmlFor="qr-verify-input"
                      className="block font-mono text-xs text-zinc-300"
                    >
                      COMPARE CONTACT QR PAYLOAD OR FINGERPRINT
                    </label>
                    <div className="mt-2 flex flex-col gap-2 sm:flex-row">
                      <input
                        id="qr-verify-input"
                        type="text"
                        value={qrInputPayload}
                        onChange={(e) => setQrInputPayload(e.target.value)}
                        placeholder="Paste scanned QR JSON payload or 32-char hex fingerprint..."
                        className="flex-1 rounded-lg border border-white/10 bg-[#11131a] px-3 py-2 font-mono text-xs text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                      />
                      <button
                        type="submit"
                        className="rounded-lg border border-violet-500/40 bg-violet-500/15 px-4 py-2 text-xs font-medium text-violet-300 hover:bg-violet-500/25"
                      >
                        Compare & Verify QR
                      </button>
                    </div>
                    {qrScanFeedback && (
                      <div
                        className={`mt-2 text-xs ${
                          qrScanFeedback.type === "success"
                            ? "text-emerald-400"
                            : "text-red-400"
                        }`}
                      >
                        {qrScanFeedback.message}
                      </div>
                    )}
                  </form>
                </>
              ) : (
                <div className="flex h-full flex-col items-center justify-center rounded-xl border border-white/[0.06] bg-[#090a0f] p-6 text-center">
                  <Shield className="h-8 w-8 text-zinc-600" />
                  <p className="mt-2 text-sm font-medium text-zinc-300">
                    Select an Active Conversation to Compare Safety Numbers
                  </p>
                  <p className="mt-1 max-w-md text-xs text-zinc-500">
                    Once you open a conversation with a peer, their public
                    Ed25519 + X25519 keys and shared 60-digit safety number will
                    appear here for manual or QR verification.
                  </p>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Section B & D: Device Trust Registry + Security Events Timeline */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* B. Device Trust Table */}
          <section
            aria-label="Device Trust Registry"
            className="rounded-xl border border-white/10 bg-[#11131a] p-5 lg:col-span-6"
          >
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-emerald-400" />
                <h2 className="text-sm font-semibold text-white">
                  B. Device Trust Management ({myDevices.length})
                </h2>
              </div>
              <span className="font-mono text-[11px] text-zinc-400">
                Account: @{currentUser.username}
              </span>
            </div>

            <div className="mt-4 space-y-3">
              {myDevices.map((dev) => {
                const isCurrentDevice =
                  localDevice && dev.fingerprint === localDevice.fingerprint;
                return (
                  <div
                    key={dev.id}
                    className={`rounded-lg border p-3.5 ${
                      dev.is_revoked
                        ? "border-red-500/25 bg-red-500/5"
                        : isCurrentDevice
                          ? "border-violet-500/35 bg-[#090a0f]"
                          : "border-white/[0.06] bg-[#090a0f]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-white">
                            {dev.device_label}
                          </span>
                          {isCurrentDevice && (
                            <span className="rounded bg-violet-500/20 px-1.5 py-0.5 font-mono text-[10px] text-violet-300">
                              THIS WORKSTATION
                            </span>
                          )}
                          {dev.is_revoked ? (
                            <span className="rounded bg-red-500/20 px-1.5 py-0.5 font-mono text-[10px] text-red-300">
                              REVOKED
                            </span>
                          ) : (
                            <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
                              TRUSTED
                            </span>
                          )}
                        </div>
                        <div className="mt-1.5 font-mono text-[11px] text-zinc-400">
                          FP: {dev.fingerprint}
                        </div>
                        <div className="mt-1 flex items-center gap-3 font-mono text-[10px] text-zinc-500">
                          <span>
                            Registered:{" "}
                            {new Date(dev.registered_at).toLocaleDateString()}
                          </span>
                          <span>
                            Active:{" "}
                            {new Date(dev.last_active_at).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      {!dev.is_revoked && !isCurrentDevice && (
                        <button
                          type="button"
                          onClick={() =>
                            void onRevokeDevice(dev.id, dev.fingerprint)
                          }
                          className="inline-flex items-center gap-1 rounded border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-[11px] font-medium text-red-300 hover:bg-red-500/20"
                        >
                          <Trash2 className="h-3 w-3" />
                          <span>Revoke</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* D. Security Event Audit Timeline */}
          <section
            aria-label="Security Events Timeline"
            className="rounded-xl border border-white/10 bg-[#11131a] p-5 lg:col-span-6"
          >
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-violet-400" />
                <h2 className="text-sm font-semibold text-white">
                  D. Cryptographic Security Event Log
                </h2>
              </div>
              <span className="font-mono text-[11px] text-zinc-400">
                Real-Time Audit Stream
              </span>
            </div>

            <div className="mt-4 max-h-96 space-y-2.5 overflow-y-auto pr-1">
              {securityEvents.length === 0 ? (
                <div className="py-8 text-center text-xs text-zinc-500">
                  No security events recorded yet.
                </div>
              ) : (
                securityEvents.map((ev) => (
                  <div
                    key={ev.id}
                    className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ${
                          ev.severity === "critical"
                            ? "bg-red-500/20 text-red-300"
                            : ev.severity === "warning"
                              ? "bg-amber-500/20 text-amber-300"
                              : ev.severity === "success"
                                ? "bg-emerald-500/20 text-emerald-300"
                                : "bg-violet-500/20 text-violet-300"
                        }`}
                      >
                        {ev.event_type.replace(/_/g, " ")}
                      </span>
                      <span className="flex items-center gap-1 font-mono text-[10px] text-zinc-500">
                        <Clock className="h-3 w-3" />
                        {new Date(ev.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="mt-1.5 text-xs font-medium text-white">
                      {ev.title}
                    </div>
                    <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-400">
                      {ev.description}
                    </p>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
