"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  Lock,
  Key,
  Cpu,
  Radio,
  Fingerprint,
  FileLock2,
  Clock,
  Terminal,
  ArrowRight,
  CheckCircle2,
  EyeOff,
  ServerOff,
  RefreshCw,
  Layers,
  Activity,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

const DEMO_CIPHERTEXTS = [
  "e4b98d12c73f0a8e91d42b6c88a7f5e1920c3b4d78e6f1a2c3d4e5f60718293a",
  "7f1c9a04d2e85b37c6104a98f2e1d3b5a7098c6e4f2a1b3c5d7e9f0a2b4c6d8e",
  "92d14e6f8a0c3b5d7e9f1a3c5e7b9d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2f",
];

export default function LandingPage() {
  const [packetIndex, setPacketIndex] = useState(0);
  const [handshakeStage, setHandshakeStage] = useState<
    "identity" | "ecdh" | "hkdf" | "aead"
  >("identity");

  useEffect(() => {
    const interval = setInterval(() => {
      setPacketIndex((prev) => (prev + 1) % DEMO_CIPHERTEXTS.length);
      setHandshakeStage((prev) => {
        if (prev === "identity") return "ecdh";
        if (prev === "ecdh") return "hkdf";
        if (prev === "hkdf") return "aead";
        return "identity";
      });
    }, 3200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#090a0f] text-[#f3f4f6] selection:bg-violet-500/30">
      {/* Subtle Top Grid Background */}
      <div
        className="pointer-events-none fixed inset-0 z-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(to right, #ffffff 1px, transparent 1px), linear-gradient(to bottom, #ffffff 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      {/* 1. Navigation Bar */}
      <header className="sticky top-0 z-50 border-b border-white/[0.075] bg-[#090a0f]/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-400">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex items-center gap-2.5">
              <span className="text-base font-semibold tracking-tight text-white">
                CipherMesh
              </span>
              <span className="hidden rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 font-mono text-[11px] text-zinc-400 sm:inline-block">
                v1.0 • E2EE P2P
              </span>
            </div>
          </div>

          <nav
            aria-label="Primary Navigation"
            className="hidden items-center gap-7 text-sm text-zinc-400 md:flex"
          >
            <a
              href="#architecture"
              className="transition-colors hover:text-white"
            >
              Architecture
            </a>
            <a
              href="#cryptography"
              className="transition-colors hover:text-white"
            >
              Cryptography
            </a>
            <a href="#features" className="transition-colors hover:text-white">
              Capabilities
            </a>
            <a href="#privacy" className="transition-colors hover:text-white">
              Privacy Principles
            </a>
          </nav>

          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="rounded-lg border border-white/10 bg-[#11131a] px-3.5 py-2 text-xs font-medium text-zinc-200 transition-colors hover:border-white/20 hover:bg-[#171a24]"
            >
              Sign In
            </Link>
            <Link
              href="/register"
              className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-violet-500"
            >
              <span>Launch Platform</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </header>

      <main className="relative z-10">
        {/* 2. Hero Section */}
        <section className="mx-auto max-w-7xl px-4 pt-16 pb-20 sm:px-6 lg:px-8 lg:pt-24">
          <div className="grid grid-cols-1 items-center gap-12 lg:grid-cols-12">
            {/* Hero Left Copy */}
            <div className="lg:col-span-6">
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-violet-500/30 bg-violet-500/10 px-3 py-1 text-xs font-medium text-violet-300">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span>Private by Architecture</span>
                <span className="text-violet-400/60">|</span>
                <span className="font-mono text-[11px] text-violet-200">
                  X25519 + XChaCha20-Poly1305
                </span>
              </div>

              <h1 className="text-4xl font-semibold tracking-tight text-white sm:text-5xl lg:text-[52px] lg:leading-[1.12]">
                Your conversations.{" "}
                <span className="text-zinc-400">Your keys.</span> Your privacy.
              </h1>

              <p className="mt-5 max-w-xl text-base leading-relaxed text-zinc-400 sm:text-lg">
                A peer-to-peer communication platform engineered around
                end-to-end encryption, device verification, and privacy by
                design.
              </p>

              <div className="mt-8 flex flex-wrap items-center gap-3.5">
                <Link
                  href="/register"
                  className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-3 text-sm font-medium text-white transition-all hover:bg-violet-500"
                >
                  <Lock className="h-4 w-4" />
                  <span>Start a Secure Conversation</span>
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <a
                  href="#architecture"
                  className="inline-flex items-center gap-2 rounded-lg border border-white/12 bg-[#11131a] px-5 py-3 text-sm font-medium text-zinc-200 transition-colors hover:border-white/25 hover:bg-[#171a24]"
                >
                  <Terminal className="h-4 w-4 text-sky-400" />
                  <span>Explore Security Architecture</span>
                </a>
              </div>

              {/* Technical Spec Strip */}
              <div className="mt-10 grid grid-cols-3 gap-4 border-t border-white/[0.075] pt-6">
                <div>
                  <div className="font-mono text-xs text-zinc-500">
                    KEY AGREEMENT
                  </div>
                  <div className="mt-1 font-mono text-sm font-medium text-zinc-200">
                    X25519 + HKDF
                  </div>
                </div>
                <div>
                  <div className="font-mono text-xs text-zinc-500">
                    AEAD CIPHER
                  </div>
                  <div className="mt-1 font-mono text-sm font-medium text-zinc-200">
                    XChaCha20-Poly1305
                  </div>
                </div>
                <div>
                  <div className="font-mono text-xs text-zinc-500">
                    SIGNATURES
                  </div>
                  <div className="mt-1 font-mono text-sm font-medium text-zinc-200">
                    Ed25519 (RFC 8032)
                  </div>
                </div>
              </div>
            </div>

            {/* Hero Right: Visual Representation of Two Devices Establishing an Encrypted Connection */}
            <div className="lg:col-span-6">
              <div className="rounded-xl border border-white/10 bg-[#11131a] p-5 shadow-2xl">
                <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
                  <div className="flex items-center gap-2">
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                    <span className="font-mono text-xs font-medium text-zinc-300">
                      LIVE CRYPTOGRAPHIC TUNNEL INSPECTOR
                    </span>
                  </div>
                  <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
                    DTLS + APP-LAYER E2EE
                  </span>
                </div>

                {/* Two Device Nodes Diagram */}
                <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-11 sm:items-center">
                  {/* Node A */}
                  <div className="rounded-lg border border-white/10 bg-[#090a0f] p-3.5 sm:col-span-4">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] text-violet-400">
                        NODE A (INITIATOR)
                      </span>
                      <Cpu className="h-4 w-4 text-violet-400" />
                    </div>
                    <div className="mt-2 text-sm font-medium text-white">
                      Alice Workstation
                    </div>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-zinc-400">
                      <div className="flex justify-between">
                        <span className="text-zinc-500">Ed25519:</span>
                        <span className="text-zinc-300">8F4A...9C12</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-500">X25519:</span>
                        <span className="text-zinc-300">3D7B...E04F</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-500">Private Key:</span>
                        <span className="text-emerald-400">Local IDB Only</span>
                      </div>
                    </div>
                  </div>

                  {/* Animated Encrypted Bridge */}
                  <div className="flex flex-col items-center justify-center py-2 sm:col-span-3">
                    <div className="mb-1.5 font-mono text-[10px] tracking-wider text-sky-400 uppercase">
                      {handshakeStage === "identity" && "1. Ed25519 Verify"}
                      {handshakeStage === "ecdh" && "2. X25519 ECDH"}
                      {handshakeStage === "hkdf" && "3. HKDF-SHA256"}
                      {handshakeStage === "aead" && "4. P2P DataChannel"}
                    </div>
                    <div className="relative flex h-8 w-full items-center justify-center">
                      <div className="h-[1px] w-full bg-white/15" />
                      <motion.div
                        key={packetIndex}
                        initial={{ x: -36, opacity: 0 }}
                        animate={{ x: 36, opacity: [0, 1, 1, 0] }}
                        transition={{
                          duration: 2.6,
                          repeat: Infinity,
                          ease: "linear",
                        }}
                        className="absolute flex items-center gap-1 rounded border border-violet-500/40 bg-[#171a24] px-2 py-0.5 font-mono text-[10px] text-violet-300"
                      >
                        <Lock className="h-2.5 w-2.5" />
                        <span>AEAD</span>
                      </motion.div>
                    </div>
                    <div className="mt-1 font-mono text-[10px] text-zinc-500">
                      ICE: host ↔ srflx
                    </div>
                  </div>

                  {/* Node B */}
                  <div className="rounded-lg border border-white/10 bg-[#090a0f] p-3.5 sm:col-span-4">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] text-sky-400">
                        NODE B (RESPONDER)
                      </span>
                      <Cpu className="h-4 w-4 text-sky-400" />
                    </div>
                    <div className="mt-2 text-sm font-medium text-white">
                      Bob Security Node
                    </div>
                    <div className="mt-2 space-y-1 font-mono text-[11px] text-zinc-400">
                      <div className="flex justify-between">
                        <span className="text-zinc-500">Ed25519:</span>
                        <span className="text-zinc-300">C219...74A8</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-500">X25519:</span>
                        <span className="text-zinc-300">9E10...5B2D</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-500">Private Key:</span>
                        <span className="text-emerald-400">Local IDB Only</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Live Wire Envelope Telemetry */}
                <div className="mt-4 rounded-lg border border-white/[0.075] bg-[#090a0f] p-3.5 font-mono text-xs">
                  <div className="flex items-center justify-between text-[11px] text-zinc-500">
                    <span>WIRE PAYLOAD ENVELOPE (ZERO-PLAINTEXT)</span>
                    <span className="text-violet-400">SEQ #00{packetIndex + 1} • EPOCH 1</span>
                  </div>
                  <div className="mt-2 space-y-1.5 text-[11px]">
                    <div className="flex items-start gap-2">
                      <span className="w-20 shrink-0 text-zinc-500">
                        CIPHERTEXT:
                      </span>
                      <span className="break-all text-zinc-300">
                        {DEMO_CIPHERTEXTS[packetIndex]}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-20 shrink-0 text-zinc-500">
                        NONCE (24B):
                      </span>
                      <span className="truncate text-sky-400">
                        4f8a21c90e7b3d15a6c89012f4e6d8c0a1b2c3d4e5f60718
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-20 shrink-0 text-zinc-500">
                        SAFETY NUM:
                      </span>
                      <span className="text-emerald-400">
                        49201 88340 12944 76109 30492 55812
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 3. Product Introduction & Security Architecture Overview */}
        <section
          id="architecture"
          className="border-t border-white/[0.075] bg-[#0c0e14] py-20"
        >
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="font-mono text-xs tracking-wider text-violet-400 uppercase">
                01 // Security Architecture Overview
              </div>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                Engineered for verifiable trust, not blind faith.
              </h2>
              <p className="mt-3 text-sm leading-relaxed text-zinc-400 sm:text-base">
                Standard messaging platforms require trusting centralized
                servers or opaque client state. CipherMesh separates signaling
                from transport, applies independent application-layer AEAD
                encryption on top of WebRTC DataChannels, and exposes every
                session parameter inside a real-time Security Center.
              </p>
            </div>

            <div className="mt-12 grid grid-cols-1 gap-6 md:grid-cols-3">
              <div className="rounded-xl border border-white/[0.075] bg-[#11131a] p-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-400">
                  <Key className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-base font-semibold text-white">
                  Client-Bound Identity Keys
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">
                  Each registered device generates an Ed25519 signing keypair
                  and a signed X25519 key-agreement keypair locally. Secret keys
                  reside exclusively in client-side storage and are never
                  transmitted to the database.
                </p>
                <div className="mt-4 border-t border-white/[0.06] pt-3 font-mono text-[11px] text-zinc-500">
                  STORAGE: IndexedDB (ciphermesh_keystore_v1)
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.075] bg-[#11131a] p-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10 text-sky-400">
                  <Radio className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-base font-semibold text-white">
                  Dual-Layer P2P + Store-and-Forward
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">
                  When both peers are online, encrypted envelopes and chunked
                  files stream directly over WebRTC DataChannels (with optional
                  TURN relay fallback). Offline recipients receive encrypted
                  ciphertext blobs via asynchronous store-and-forward.
                </p>
                <div className="mt-4 border-t border-white/[0.06] pt-3 font-mono text-[11px] text-zinc-500">
                  TRANSPORT: WebRTC SCTP + Encrypted Sync
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.075] bg-[#11131a] p-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                  <Fingerprint className="h-5 w-5" />
                </div>
                <h3 className="mt-4 text-base font-semibold text-white">
                  Cryptographic Safety Numbers
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-zinc-400">
                  CipherMesh clearly distinguishes a merely connected session
                  from a cryptographically verified peer. Compare 60-digit
                  safety numbers or scan identity QR codes to lock in verified
                  trust and detect unexpected key changes.
                </p>
                <div className="mt-4 border-t border-white/[0.06] pt-3 font-mono text-[11px] text-zinc-500">
                  VERIFICATION: SHA-256 Canonical Fingerprint
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 4. How Encryption Works (Step-by-Step Pipeline) */}
        <section id="cryptography" className="py-20">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="font-mono text-xs tracking-wider text-sky-400 uppercase">
                02 // How Encryption Works
              </div>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                End-to-End Cryptographic Lifecycle
              </h2>
              <p className="mt-3 text-sm leading-relaxed text-zinc-400 sm:text-base">
                Every message and file chunk passes through an audited,
                deterministic 4-stage pipeline powered by{" "}
                <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-zinc-200">
                  @noble/curves
                </code>
                ,{" "}
                <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-zinc-200">
                  @noble/hashes
                </code>
                , and{" "}
                <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-zinc-200">
                  @noble/ciphers
                </code>
                .
              </p>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-4 lg:grid-cols-4">
              {[
                {
                  step: "STAGE 01",
                  title: "Signed Identity Binding",
                  primitive: "Ed25519 + X25519",
                  desc: "Device generates an Ed25519 identity keypair and signs its X25519 public key. Peers verify this signature before any key agreement occurs.",
                },
                {
                  step: "STAGE 02",
                  title: "Per-Message Key Derivation",
                  primitive: "X25519 ECDH + HKDF-SHA256",
                  desc: "Each message generates a fresh 256-bit ephemeral public value mixed with the X25519 shared secret, conversation ID, sequence number, and session epoch via HKDF-SHA256.",
                },
                {
                  step: "STAGE 03",
                  title: "Authenticated Encryption",
                  primitive: "XChaCha20-Poly1305 (192-bit Nonce)",
                  desc: "Plaintext JSON and metadata AAD (sequence, epoch, sender keys) are encrypted with a fresh 24-byte CSPRNG nonce and authenticated with a 128-bit Poly1305 tag.",
                },
                {
                  step: "STAGE 04",
                  title: "Transcript Signing & Replay Check",
                  primitive: "Ed25519 Sign + Sliding Window",
                  desc: "The entire AAD + ciphertext transcript is signed with the sender's Ed25519 secret key. Recipients verify the signature and reject duplicate nonces or replayed sequence numbers.",
                },
              ].map((item) => (
                <div
                  key={item.step}
                  className="flex flex-col justify-between rounded-xl border border-white/[0.075] bg-[#11131a] p-5"
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-violet-400">
                        {item.step}
                      </span>
                      <span className="rounded border border-white/10 bg-white/[0.03] px-2 py-0.5 font-mono text-[10px] text-zinc-300">
                        {item.primitive}
                      </span>
                    </div>
                    <h3 className="mt-3 text-base font-semibold text-white">
                      {item.title}
                    </h3>
                    <p className="mt-2 text-xs leading-relaxed text-zinc-400">
                      {item.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* 5. Feature Showcase */}
        <section
          id="features"
          className="border-t border-white/[0.075] bg-[#0c0e14] py-20"
        >
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="font-mono text-xs tracking-wider text-emerald-400 uppercase">
                03 // Platform Capabilities
              </div>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                Built for operational security and daily communication.
              </h2>
            </div>

            <div className="mt-10 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {[
                {
                  icon: Shield,
                  title: "Transparent Security Center",
                  desc: "Inspect active session IDs, key fingerprints, ICE candidate topology (Direct P2P vs TURN Relay), device trust status, and live cryptographic security events.",
                },
                {
                  icon: FileLock2,
                  title: "Encrypted P2P File Transfer",
                  desc: "Share files with per-chunk XChaCha20-Poly1305 encryption, pause/resume/cancel controls, and whole-file SHA-256 integrity verification before download.",
                },
                {
                  icon: Clock,
                  title: "Configurable Ephemeral Messaging",
                  desc: "Set disappearing message timers (30s, 1m, 5m, 1h, 24h) enforced across devices with honest disclosure of recipient-side capture boundaries.",
                },
                {
                  icon: RefreshCw,
                  title: "Explicit Session Key Rotation",
                  desc: "Rotate conversation session epochs and device key versions on demand, immediately invalidating prior session contexts and logging an audit event.",
                },
                {
                  icon: Layers,
                  title: "Device Trust & Revocation",
                  desc: "Inspect every device registered to your account or your contact's account. Revoke compromised devices immediately with cryptographic audit trails.",
                },
                {
                  icon: Activity,
                  title: "Replay & Tamper Defense",
                  desc: "Sliding-window sequence tracking and strict 192-bit nonce deduplication detect and block replayed packets or tampered ciphertext envelopes.",
                },
              ].map((feat) => {
                const Icon = feat.icon;
                return (
                  <div
                    key={feat.title}
                    className="rounded-xl border border-white/[0.075] bg-[#11131a] p-5 transition-colors hover:border-white/15"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-[#171a24] text-violet-400">
                        <Icon className="h-4 w-4" />
                      </div>
                      <h3 className="text-sm font-semibold text-white">
                        {feat.title}
                      </h3>
                    </div>
                    <p className="mt-3 text-xs leading-relaxed text-zinc-400">
                      {feat.desc}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* 6. Privacy Principles & Honest Threat Boundaries */}
        <section id="privacy" className="py-20">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-1 gap-10 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <div className="font-mono text-xs tracking-wider text-violet-400 uppercase">
                  04 // Privacy Principles
                </div>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                  Zero-Plaintext Architecture & Honest Disclosures
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-zinc-400">
                  Credible security engineering requires stating both what the
                  cryptography guarantees and what metadata or endpoint risks
                  remain outside any network protocol&apos;s control.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-7">
                <div className="rounded-xl border border-emerald-500/20 bg-[#11131a] p-5">
                  <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>WHAT CIPHERMESH GUARANTEES</span>
                  </div>
                  <ul className="mt-3 space-y-2.5 text-xs leading-relaxed text-zinc-300">
                    <li>
                      • Plaintext messages and files are encrypted client-side
                      before touching WebRTC or Supabase.
                    </li>
                    <li>
                      • Database records store only authenticated ciphertext,
                      24-byte nonces, public keys, and routing metadata.
                    </li>
                    <li>
                      • Private keys never leave your browser&apos;s local
                      IndexedDB keystore.
                    </li>
                    <li>
                      • Every envelope is verified with Ed25519 and Poly1305
                      before rendering.
                    </li>
                  </ul>
                </div>

                <div className="rounded-xl border border-amber-500/20 bg-[#11131a] p-5">
                  <div className="flex items-center gap-2 text-xs font-semibold text-amber-400">
                    <EyeOff className="h-4 w-4" />
                    <span>TRANSPARENT BOUNDARIES</span>
                  </div>
                  <ul className="mt-3 space-y-2.5 text-xs leading-relaxed text-zinc-300">
                    <li>
                      • Not every WebRTC session is direct P2P: symmetric NATs
                      require TURN relaying or encrypted store-and-forward.
                    </li>
                    <li>
                      • Connected ≠ Verified: a session is only identity-verified
                      after comparing safety numbers or QR fingerprints.
                    </li>
                    <li>
                      • Ephemeral timers delete messages across honest clients
                      and storage, but cannot prevent external cameras or OS
                      screenshots.
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 7. Call to Action */}
        <section className="border-t border-white/[0.075] bg-[#11131a] py-16">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-6 px-4 sm:px-6 md:flex-row md:items-center lg:px-8">
            <div>
              <h2 className="text-2xl font-semibold tracking-tight text-white">
                Ready to inspect your communication security?
              </h2>
              <p className="mt-1.5 text-sm text-zinc-400">
                Generate your local Ed25519 + X25519 device identity in seconds
                and establish an encrypted session.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Link
                href="/register"
                className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-violet-500"
              >
                <span>Create Cryptographic Identity</span>
                <ChevronRight className="h-4 w-4" />
              </Link>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 rounded-lg border border-white/12 bg-[#090a0f] px-5 py-2.5 text-sm font-medium text-zinc-200 transition-colors hover:border-white/25"
              >
                <span>Access Existing Node</span>
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* 8. Footer */}
      <footer className="border-t border-white/[0.075] bg-[#090a0f] py-10">
        <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-6 px-4 sm:flex-row sm:items-center sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-violet-500/40 bg-violet-500/10 text-violet-400">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <span className="text-sm font-semibold text-white">
                CipherMesh
              </span>
              <span className="ml-2 font-mono text-xs text-zinc-500">
                Private by Architecture.
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 text-xs text-zinc-500">
            <span className="font-mono">
              SUITE: X25519-HKDF-SHA256-XChaCha20-Poly1305-Ed25519
            </span>
            <Link href="/login" className="hover:text-zinc-300">
              Sign In
            </Link>
            <Link href="/register" className="hover:text-zinc-300">
              Register
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
