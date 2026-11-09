"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield,
  Eye,
  EyeOff,
  ArrowRight,
  AlertCircle,
  Loader2,
  Cpu,
  CheckCircle2,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import { ensureDeviceRegisteredWithBackend } from "@/lib/crypto/device-sync";

export default function RegisterPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [deviceLabel, setDeviceLabel] = useState("Primary Security Workstation");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const cleanUsername = username
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "");
    const cleanDisplayName = displayName.trim() || cleanUsername;
    const cleanEmail = email.trim().toLowerCase();

    if (cleanUsername.length < 3) {
      setError(
        "Username must be at least 3 characters (letters, numbers, underscores, or hyphens)."
      );
      return;
    }
    if (!cleanEmail.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();

      // Check if username is already taken
      const { data: existingProfile } = await supabase
        .from("profiles")
        .select("id")
        .eq("username", cleanUsername)
        .maybeSingle();

      if (existingProfile) {
        setError(`Username "@${cleanUsername}" is already registered.`);
        setLoading(false);
        return;
      }

      const { data, error: signUpError } = await supabase.auth.signUp({
        email: cleanEmail,
        password,
        options: {
          data: {
            username: cleanUsername,
            display_name: cleanDisplayName,
          },
        },
      });

      if (signUpError || !data.user) {
        setError(
          signUpError?.message ||
            "Registration failed. Please verify your details."
        );
        setLoading(false);
        return;
      }

      // Ensure profile is upserted with exact display name and username
      await supabase.from("profiles").upsert({
        id: data.user.id,
        username: cleanUsername,
        display_name: cleanDisplayName,
      });

      // Generate local Ed25519 + X25519 keypair and publish public keys to devices table
      await ensureDeviceRegisteredWithBackend(
        supabase,
        data.user.id,
        deviceLabel.trim() || "Primary Security Workstation"
      );

      router.push("/app");
      router.refresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "An unexpected error occurred during registration."
      );
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col justify-between bg-[#090a0f] text-[#f3f4f6]">
      <header className="border-b border-white/[0.075] bg-[#090a0f]/80">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-400">
              <Shield className="h-4 w-4" />
            </div>
            <span className="text-sm font-semibold tracking-tight text-white">
              CipherMesh
            </span>
          </Link>
          <Link
            href="/login"
            className="text-xs text-zinc-400 transition-colors hover:text-white"
          >
            Already registered?{" "}
            <span className="font-medium text-violet-400">Sign In →</span>
          </Link>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-lg flex-1 flex-col justify-center px-4 py-10">
        <div className="rounded-xl border border-white/10 bg-[#11131a] p-6 sm:p-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-400">
              <Cpu className="h-4 w-4" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">
                Provision Cryptographic Identity
              </h1>
              <p className="text-xs text-zinc-400">
                Create your account and generate local Ed25519 + X25519 keys
              </p>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="mt-5 flex items-start gap-2.5 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleRegister} className="mt-6 space-y-4" noValidate>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="reg-username"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Handle / Username
                </label>
                <input
                  id="reg-username"
                  name="username"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="alice_sec"
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 font-mono text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                />
              </div>

              <div>
                <label
                  htmlFor="reg-display-name"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Display Name
                </label>
                <input
                  id="reg-display-name"
                  name="displayName"
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Alice Vance"
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="reg-email"
                className="block text-xs font-medium text-zinc-300"
              >
                Email Address
              </label>
              <input
                id="reg-email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="alice@ciphermesh.sec"
                className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="reg-password"
                className="block text-xs font-medium text-zinc-300"
              >
                Master Password (min. 8 characters)
              </label>
              <div className="relative mt-1.5">
                <input
                  id="reg-password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg border border-white/10 bg-[#090a0f] py-2.5 pr-10 pl-3.5 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-zinc-500 hover:text-zinc-300"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label
                htmlFor="reg-device-label"
                className="block text-xs font-medium text-zinc-300"
              >
                Device Node Identifier Label
              </label>
              <input
                id="reg-device-label"
                name="deviceLabel"
                type="text"
                value={deviceLabel}
                onChange={(e) => setDeviceLabel(e.target.value)}
                placeholder="Primary Security Workstation"
                className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Generating Ed25519 + X25519 Keypairs...</span>
                </>
              ) : (
                <>
                  <span>Generate Keys & Create Identity</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 rounded-lg border border-white/[0.06] bg-[#090a0f] p-3.5">
            <div className="flex items-center gap-2 text-xs font-medium text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Local Cryptographic Provisioning</span>
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">
              Upon registration, your browser generates a 256-bit Ed25519
              signing keypair and 256-bit X25519 ECDH keypair. Only the signed
              public keys and SHA-256 fingerprint are published to the directory.
            </p>
          </div>
        </div>
      </main>

      <footer className="border-t border-white/[0.075] py-5 text-center font-mono text-xs text-zinc-600">
        CipherMesh — Private by Architecture.
      </footer>
    </div>
  );
}
