"use client";

import React, { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Cpu,
  Radio,
  RefreshCw,
  CheckCircle2,
  X,
  Copy,
  Check,
  AlertTriangle,
  QrCode,
  ExternalLink,
} from "lucide-react";
import type {
  DeviceRecord,
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

interface ContactSecuritySidebarProps {
  currentUser: UserProfile;
  localDevice: DeviceIdentityBundle | null;
  peerProfile: UserProfile;
  peerDevices: DeviceRecord[];
  activeConversationId: string;
  sessionEpoch: number;
  ephemeralTtlSeconds: number | null;
  telemetry: WebRTCConnectionTelemetry | null;
  verifications: ContactVerificationRecord[];
  isPeerOnline: boolean;
  identityChangedFrom: string | null;
  onClose: () => void;
  onVerifyPeer: (
    peerId: string,
    peerDeviceId: string | null,
    fingerprint: string,
    safetyNumber: string,
    method: "manual" | "qr_scan"
  ) => Promise<void>;
  onRotateSessionKeys: () => Promise<void>;
  onOpenFullSecurityCenter: () => void;
}

export function ContactSecuritySidebar({
  currentUser,
  localDevice,
  peerProfile,
  peerDevices,
  activeConversationId,
  sessionEpoch,
  ephemeralTtlSeconds,
  telemetry,
  verifications,
  isPeerOnline,
  identityChangedFrom,
  onClose,
  onVerifyPeer,
  onRotateSessionKeys,
  onOpenFullSecurityCenter,
}: ContactSecuritySidebarProps) {
  const [copied, setCopied] = useState(false);
  const [showQr, setShowQr] = useState(false);

  const primaryPeerDevice =
    peerDevices.find((d) => !d.is_revoked) ?? peerDevices[0] ?? null;

  const isVerified = Boolean(
    primaryPeerDevice &&
      verifications.some(
        (v) =>
          v.contact_user_id === peerProfile.id &&
          v.verified_fingerprint === primaryPeerDevice.fingerprint &&
          v.is_verified
      )
  );

  const safetyNumber =
    localDevice && primaryPeerDevice
      ? computeSafetyNumber(
          {
            userId: currentUser.id,
            ed25519PublicKeyHex: localDevice.ed25519PublicKeyHex,
            x25519PublicKeyHex: localDevice.x25519PublicKeyHex,
          },
          {
            userId: peerProfile.id,
            ed25519PublicKeyHex: primaryPeerDevice.ed25519_public_key,
            x25519PublicKeyHex: primaryPeerDevice.x25519_public_key,
          }
        )
      : null;

  const sessionId =
    localDevice && primaryPeerDevice
      ? deriveSessionIdentifier(
          activeConversationId,
          localDevice.x25519PublicKeyHex,
          primaryPeerDevice.x25519_public_key,
          sessionEpoch
        )
      : "PENDING-KEY-SYNC";

  const peerQrPayload = primaryPeerDevice
    ? JSON.stringify({
        p: "CipherMesh-v1",
        uid: peerProfile.id,
        u: peerProfile.username,
        fp: primaryPeerDevice.fingerprint,
        ed: primaryPeerDevice.ed25519_public_key,
        x: primaryPeerDevice.x25519_public_key,
      })
    : "";

  return (
    <aside
      aria-label="Contact Security Inspector"
      className="flex h-full w-full flex-col border-l border-white/[0.075] bg-[#11131a] lg:w-80 xl:w-96"
    >
      {/* Top Bar */}
      <div className="flex h-14 items-center justify-between border-b border-white/[0.075] px-4">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-violet-400" />
          <span className="text-xs font-semibold tracking-wide text-white uppercase">
            Contact & Session Inspector
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close contextual inspector"
          className="rounded-lg p-1.5 text-zinc-400 hover:bg-white/[0.06] hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto p-4">
        {/* Contact Header */}
        <div className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4">
          <div className="flex items-center gap-3">
            <div
              className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-white/15 font-mono text-sm font-semibold text-white"
              style={{ backgroundColor: peerProfile.avatar_color || "#7C3AED" }}
            >
              {peerProfile.display_name.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-semibold text-white">
                {peerProfile.display_name}
              </div>
              <div className="truncate font-mono text-xs text-zinc-400">
                @{peerProfile.username}
              </div>
              <div className="mt-1 flex items-center gap-1.5 text-[11px]">
                <span
                  className={`h-2 w-2 rounded-full ${
                    isPeerOnline ? "bg-emerald-400" : "bg-zinc-600"
                  }`}
                />
                <span
                  className={
                    isPeerOnline ? "text-emerald-400" : "text-zinc-500"
                  }
                >
                  {isPeerOnline
                    ? "Online (Presence Active)"
                    : "Offline (Encrypted Sync)"}
                </span>
              </div>
            </div>
          </div>

          {/* Identity Verification Badge */}
          <div className="mt-3.5 border-t border-white/[0.06] pt-3">
            {identityChangedFrom ? (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-[11px] text-amber-200">
                <div className="flex items-center gap-1.5 font-semibold text-amber-300">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Identity Key Changed!</span>
                </div>
                <p className="mt-1">
                  Previous verified fingerprint ({identityChangedFrom}) changed.
                  Re-verify safety numbers before trusting this session.
                </p>
              </div>
            ) : isVerified ? (
              <div className="flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
                <div className="flex items-center gap-2 font-medium">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span>Verified Cryptographic Identity</span>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-200">
                <div className="flex items-center gap-1.5 font-medium text-amber-300">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400" />
                  <span>Connected — Identity Unverified</span>
                </div>
                <p className="mt-1 text-[11px] text-amber-200/80">
                  Messages are end-to-end encrypted, but you have not yet
                  compared safety numbers with @{peerProfile.username}.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Session & Transport Parameters */}
        <div className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] font-semibold text-zinc-400 uppercase">
              Session Cryptography
            </span>
            <span className="rounded bg-violet-500/15 px-1.5 py-0.5 font-mono text-[10px] text-violet-300">
              EPOCH {sessionEpoch}
            </span>
          </div>

          <div className="mt-3 space-y-2.5 font-mono text-[11px]">
            <div>
              <div className="text-[10px] text-zinc-500">SESSION ID</div>
              <div className="mt-0.5 text-white">{sessionId}</div>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500">CIPHER SUITE</div>
              <div className="mt-0.5 text-violet-300 break-all">
                {CIPHERMESH_ALGORITHM_SUITE}
              </div>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500">TRANSPORT PATH</div>
              <div className="mt-0.5 flex items-center gap-1.5 text-sky-400">
                <Radio className="h-3 w-3" />
                <span>
                  {telemetry?.topology === "direct_p2p"
                    ? "WebRTC Direct P2P DataChannel"
                    : telemetry?.topology === "turn_relay"
                      ? "WebRTC TURN-Relayed DataChannel"
                      : "Encrypted Store-and-Forward"}
                </span>
              </div>
            </div>
            <div>
              <div className="text-[10px] text-zinc-500">
                EPHEMERAL EXPIRY POLICY
              </div>
              <div className="mt-0.5 text-zinc-300">
                {ephemeralTtlSeconds
                  ? `Active (${ephemeralTtlSeconds}s auto-expiry)`
                  : "Persistent Encrypted History"}
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => void onRotateSessionKeys()}
            className="mt-3.5 flex w-full items-center justify-center gap-1.5 rounded-lg border border-white/10 bg-[#11131a] px-3 py-2 text-xs font-medium text-zinc-200 transition-colors hover:border-violet-500/40 hover:text-white"
          >
            <RefreshCw className="h-3.5 w-3.5 text-violet-400" />
            <span>Rotate Conversation Session Epoch</span>
          </button>
        </div>

        {/* Public Identity Fingerprint & Safety Number */}
        {primaryPeerDevice && (
          <div className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] font-semibold text-zinc-400 uppercase">
                Safety Number & Fingerprint
              </span>
              <button
                type="button"
                onClick={() => setShowQr((prev) => !prev)}
                className="inline-flex items-center gap-1 font-mono text-[10px] text-violet-400 hover:text-violet-300"
              >
                <QrCode className="h-3 w-3" />
                <span>{showQr ? "Hide QR" : "Show QR"}</span>
              </button>
            </div>

            {showQr && peerQrPayload && (
              <div className="mt-3 flex flex-col items-center rounded-lg border border-white/10 bg-white p-3">
                <QRCodeSVG value={peerQrPayload} size={136} level="M" />
                <span className="mt-1.5 font-mono text-[10px] text-zinc-800">
                  @{peerProfile.username} Identity QR
                </span>
              </div>
            )}

            <div className="mt-3">
              <div className="flex items-center justify-between font-mono text-[10px] text-zinc-500">
                <span>PEER FINGERPRINT</span>
                <button
                  type="button"
                  onClick={() => {
                    if (typeof navigator !== "undefined" && navigator.clipboard) {
                      void navigator.clipboard.writeText(
                        primaryPeerDevice.fingerprint
                      );
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1800);
                    }
                  }}
                  className="inline-flex items-center gap-1 text-zinc-400 hover:text-white"
                >
                  {copied ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <div className="mt-1 rounded border border-white/[0.06] bg-[#11131a] p-2 font-mono text-[11px] text-sky-400">
                {primaryPeerDevice.fingerprint}
              </div>
            </div>

            {safetyNumber && (
              <div className="mt-3">
                <div className="font-mono text-[10px] text-zinc-500">
                  SHARED 60-DIGIT SAFETY NUMBER
                </div>
                <div className="mt-1 grid grid-cols-3 gap-1.5 rounded border border-white/[0.06] bg-[#11131a] p-2.5 font-mono text-[11px] tracking-wider text-emerald-300">
                  {safetyNumber.split(" ").map((blk, i) => (
                    <span key={i} className="text-center">
                      {blk}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {safetyNumber && (
              <button
                type="button"
                onClick={() =>
                  void onVerifyPeer(
                    peerProfile.id,
                    primaryPeerDevice.id,
                    primaryPeerDevice.fingerprint,
                    safetyNumber,
                    "manual"
                  )
                }
                className={`mt-3.5 flex w-full items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
                  isVerified
                    ? "border border-emerald-500/30 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25"
                    : "bg-emerald-600 text-white hover:bg-emerald-500"
                }`}
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>
                  {isVerified
                    ? "Identity Verified (Click to Re-Confirm)"
                    : "Mark Contact Identity as Verified"}
                </span>
              </button>
            )}
          </div>
        )}

        {/* Contact's Registered Devices */}
        <div className="rounded-xl border border-white/[0.06] bg-[#090a0f] p-4">
          <div className="flex items-center gap-1.5 font-mono text-[11px] font-semibold text-zinc-400 uppercase">
            <Cpu className="h-3.5 w-3.5 text-violet-400" />
            <span>Peer Registered Devices ({peerDevices.length})</span>
          </div>

          <div className="mt-3 space-y-2">
            {peerDevices.map((dev) => (
              <div
                key={dev.id}
                className="rounded-lg border border-white/[0.06] bg-[#11131a] p-2.5 font-mono text-[11px]"
              >
                <div className="flex items-center justify-between">
                  <span className="font-sans font-medium text-white">
                    {dev.device_label}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[9px] ${
                      dev.is_revoked
                        ? "bg-red-500/20 text-red-300"
                        : "bg-emerald-500/15 text-emerald-300"
                    }`}
                  >
                    {dev.is_revoked ? "REVOKED" : "ACTIVE"}
                  </span>
                </div>
                <div className="mt-1 truncate text-[10px] text-zinc-400">
                  {dev.fingerprint}
                </div>
              </div>
            ))}
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenFullSecurityCenter}
          className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2.5 text-xs font-medium text-violet-300 hover:bg-violet-500/20"
        >
          <span>Open Full Security Center</span>
          <ExternalLink className="h-3.5 w-3.5" />
        </button>
      </div>
    </aside>
  );
}
