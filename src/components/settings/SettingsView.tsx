"use client";

import React, { useState } from "react";
import {
  User,
  Shield,
  Sliders,
  Save,
  CheckCircle2,
  AlertCircle,
  Key,
  HardDrive,
  Clock,
  Radio,
} from "lucide-react";
import type {
  UserProfile,
  UserPreferencesRecord,
} from "@/types/ciphermesh";
import type { DeviceIdentityBundle } from "@/lib/crypto/engine";

interface SettingsViewProps {
  currentUser: UserProfile;
  localDevice: DeviceIdentityBundle | null;
  preferences: UserPreferencesRecord;
  onUpdateProfile: (updates: {
    display_name: string;
    bio: string;
    status_text: string;
    avatar_color: string;
  }) => Promise<void>;
  onUpdatePreferences: (
    updates: Partial<UserPreferencesRecord>
  ) => Promise<void>;
}

const AVATAR_COLORS = [
  "#7C3AED",
  "#2563EB",
  "#059669",
  "#D97706",
  "#DC2626",
  "#4F46E5",
  "#0891B2",
];

export function SettingsView({
  currentUser,
  localDevice,
  preferences,
  onUpdateProfile,
  onUpdatePreferences,
}: SettingsViewProps) {
  const [displayName, setDisplayName] = useState(currentUser.display_name);
  const [bio, setBio] = useState(currentUser.bio || "");
  const [statusText, setStatusText] = useState(
    currentUser.status_text || "Online — Private by Architecture"
  );
  const [avatarColor, setAvatarColor] = useState(
    currentUser.avatar_color || "#7C3AED"
  );

  const [maxFileSizeMb, setMaxFileSizeMb] = useState(
    preferences.max_file_size_mb ?? 25
  );
  const [defaultTtl, setDefaultTtl] = useState<number | null>(
    preferences.default_ephemeral_ttl ?? null
  );
  const [allowTurn, setAllowTurn] = useState(
    preferences.allow_turn_relay ?? true
  );
  const [forceTurn, setForceTurn] = useState(
    preferences.force_turn_relay ?? false
  );
  const [showTyping, setShowTyping] = useState(
    preferences.show_typing_indicators ?? true
  );
  const [showReceipts, setShowReceipts] = useState(
    preferences.show_read_receipts ?? true
  );

  const [saving, setSaving] = useState(false);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);
  const [errorNotice, setErrorNotice] = useState<string | null>(null);

  async function handleSaveAll(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSavedNotice(null);
    setErrorNotice(null);

    try {
      await onUpdateProfile({
        display_name: displayName.trim() || currentUser.username,
        bio: bio.trim(),
        status_text: statusText.trim(),
        avatar_color: avatarColor,
      });

      await onUpdatePreferences({
        max_file_size_mb: Math.min(100, Math.max(1, Number(maxFileSizeMb) || 25)),
        default_ephemeral_ttl: defaultTtl,
        allow_turn_relay: allowTurn,
        force_turn_relay: forceTurn,
        show_typing_indicators: showTyping,
        show_read_receipts: showReceipts,
      });

      setSavedNotice("Operator profile and security preferences updated.");
      setTimeout(() => setSavedNotice(null), 3500);
    } catch (err) {
      setErrorNotice(
        err instanceof Error ? err.message : "Failed to save settings."
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex-1 overflow-y-auto bg-[#090a0f] p-4 sm:p-6 lg:p-8">
      <div className="mx-auto max-w-4xl space-y-6">
        <div className="border-b border-white/[0.075] pb-5">
          <div className="flex items-center gap-2 font-mono text-xs text-violet-400">
            <Sliders className="h-3.5 w-3.5" />
            <span>NODE & OPERATOR CONFIGURATION</span>
          </div>
          <h1 className="mt-1 text-xl font-semibold tracking-tight text-white sm:text-2xl">
            Profile & Security Preferences
          </h1>
          <p className="mt-1 text-xs text-zinc-400">
            Manage your public operator identity, WebRTC transport policies,
            ephemeral defaults, and encrypted file transfer limits.
          </p>
        </div>

        {savedNotice && (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{savedNotice}</span>
          </div>
        )}

        {errorNotice && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
            <span>{errorNotice}</span>
          </div>
        )}

        <form onSubmit={handleSaveAll} className="space-y-6">
          {/* Operator Identity */}
          <section className="rounded-xl border border-white/10 bg-[#11131a] p-5">
            <div className="flex items-center gap-2 border-b border-white/[0.075] pb-3.5">
              <User className="h-4 w-4 text-violet-400" />
              <h2 className="text-sm font-semibold text-white">
                Operator Profile (@{currentUser.username})
              </h2>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="settings-display-name"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Display Name
                </label>
                <input
                  id="settings-display-name"
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
                />
              </div>

              <div>
                <label
                  htmlFor="settings-status"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Public Status Line
                </label>
                <input
                  id="settings-status"
                  type="text"
                  value={statusText}
                  onChange={(e) => setStatusText(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
                />
              </div>

              <div className="sm:col-span-2">
                <label
                  htmlFor="settings-bio"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Security Bio / PGP or Out-of-Band Note
                </label>
                <textarea
                  id="settings-bio"
                  rows={2}
                  value={bio}
                  onChange={(e) => setBio(e.target.value)}
                  placeholder="Optional out-of-band contact note..."
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                />
              </div>

              <div className="sm:col-span-2">
                <span className="block text-xs font-medium text-zinc-300">
                  Node Avatar Accent
                </span>
                <div className="mt-2 flex items-center gap-2.5">
                  {AVATAR_COLORS.map((col) => (
                    <button
                      key={col}
                      type="button"
                      onClick={() => setAvatarColor(col)}
                      aria-label={`Select color ${col}`}
                      className={`h-7 w-7 rounded-lg border transition-transform ${
                        avatarColor === col
                          ? "scale-110 border-white"
                          : "border-white/15 opacity-75"
                      }`}
                      style={{ backgroundColor: col }}
                    />
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* Transport, File Limits & Ephemeral Defaults */}
          <section className="rounded-xl border border-white/10 bg-[#11131a] p-5">
            <div className="flex items-center gap-2 border-b border-white/[0.075] pb-3.5">
              <Shield className="h-4 w-4 text-sky-400" />
              <h2 className="text-sm font-semibold text-white">
                Transport & Cryptographic Policy
              </h2>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <label
                  htmlFor="settings-max-file"
                  className="flex items-center gap-1.5 text-xs font-medium text-white"
                >
                  <HardDrive className="h-3.5 w-3.5 text-violet-400" />
                  <span>Configurable Maximum File Size (MB)</span>
                </label>
                <p className="mt-1 text-[11px] text-zinc-400">
                  Maximum size per encrypted file transfer (1 MB – 100 MB).
                </p>
                <input
                  id="settings-max-file"
                  type="number"
                  min={1}
                  max={100}
                  value={maxFileSizeMb}
                  onChange={(e) => setMaxFileSizeMb(Number(e.target.value))}
                  className="mt-2 w-full rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 font-mono text-xs text-white focus:border-violet-500 focus:outline-none"
                />
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <label
                  htmlFor="settings-default-ttl"
                  className="flex items-center gap-1.5 text-xs font-medium text-white"
                >
                  <Clock className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Default Disappearing Message Timer</span>
                </label>
                <p className="mt-1 text-[11px] text-zinc-400">
                  Applied to new conversations by default.
                </p>
                <select
                  id="settings-default-ttl"
                  value={defaultTtl ?? ""}
                  onChange={(e) =>
                    setDefaultTtl(
                      e.target.value === "" ? null : Number(e.target.value)
                    )
                  }
                  className="mt-2 w-full rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 text-xs text-white focus:border-violet-500 focus:outline-none"
                >
                  <option value="">Disabled (Persistent Ciphertext)</option>
                  <option value="30">30 seconds</option>
                  <option value="60">1 minute</option>
                  <option value="300">5 minutes</option>
                  <option value="3600">1 hour</option>
                  <option value="86400">24 hours</option>
                </select>
              </div>

              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-medium text-white">
                    <Radio className="h-3.5 w-3.5 text-sky-400" />
                    <span>Allow TURN Relay Fallback</span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-zinc-400">
                    Use TURN relay when symmetric NAT blocks direct P2P.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={allowTurn}
                  onChange={(e) => setAllowTurn(e.target.checked)}
                  className="h-4 w-4 accent-violet-600"
                />
              </div>

              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <div>
                  <div className="text-xs font-medium text-white">
                    Force TURN Relay (IP Masking Mode)
                  </div>
                  <p className="mt-0.5 text-[11px] text-zinc-400">
                    Avoid exposing local ICE host candidates when TURN is
                    configured.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={forceTurn}
                  onChange={(e) => setForceTurn(e.target.checked)}
                  className="h-4 w-4 accent-violet-600"
                />
              </div>

              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <div>
                  <div className="text-xs font-medium text-white">
                    Broadcast Typing Indicators
                  </div>
                  <p className="mt-0.5 text-[11px] text-zinc-400">
                    Notify active peer when composing a message.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={showTyping}
                  onChange={(e) => setShowTyping(e.target.checked)}
                  className="h-4 w-4 accent-violet-600"
                />
              </div>

              <div className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
                <div>
                  <div className="text-xs font-medium text-white">
                    Send Encrypted Read Receipts
                  </div>
                  <p className="mt-0.5 text-[11px] text-zinc-400">
                    Acknowledge when decrypted messages are viewed.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={showReceipts}
                  onChange={(e) => setShowReceipts(e.target.checked)}
                  className="h-4 w-4 accent-violet-600"
                />
              </div>
            </div>
          </section>

          {/* Local Cryptographic Keystore Summary (Public Material Only) */}
          <section className="rounded-xl border border-white/10 bg-[#11131a] p-5">
            <div className="flex items-center gap-2 border-b border-white/[0.075] pb-3.5">
              <Key className="h-4 w-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-white">
                Local Workstation Public Key Material
              </h2>
            </div>

            <div className="mt-3 space-y-2 font-mono text-xs">
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  ED25519 IDENTITY PUBLIC KEY (HEX)
                </div>
                <div className="mt-1 break-all text-zinc-300">
                  {localDevice?.ed25519PublicKeyHex ?? "—"}
                </div>
              </div>
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  X25519 ECDH PUBLIC KEY (HEX)
                </div>
                <div className="mt-1 break-all text-zinc-300">
                  {localDevice?.x25519PublicKeyHex ?? "—"}
                </div>
              </div>
            </div>
          </section>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-violet-500 disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              <span>{saving ? "Saving Configuration..." : "Save Settings"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
