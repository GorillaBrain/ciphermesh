"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  AlertCircle,
  Loader2,
  KeyRound,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import { ensureDeviceRegisteredWithBackend } from "@/lib/crypto/device-sync";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!email.trim() || !password) {
      setError("Please enter both your email address and password.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const { data, error: signInError } =
        await supabase.auth.signInWithPassword({
          email: email.trim().toLowerCase(),
          password,
        });

      if (signInError || !data.user) {
        setError(
          signInError?.message ||
            "Authentication failed. Verify your credentials and try again."
        );
        setLoading(false);
        return;
      }

      // Ensure local cryptographic device identity is generated and synchronized
      await ensureDeviceRegisteredWithBackend(supabase, data.user.id);

      router.push("/app");
      router.refresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "An unexpected error occurred during authentication."
      );
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col justify-between bg-[#090a0f] text-[#f3f4f6]">
      {/* Top Bar */}
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
            href="/register"
            className="text-xs text-zinc-400 transition-colors hover:text-white"
          >
            Need a cryptographic identity?{" "}
            <span className="font-medium text-violet-400">Register Node →</span>
          </Link>
        </div>
      </header>

      {/* Main Auth Card */}
      <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center px-4 py-12">
        <div className="rounded-xl border border-white/10 bg-[#11131a] p-6 sm:p-8">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-400">
              <KeyRound className="h-4 w-4" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">
                Authenticate Node
              </h1>
              <p className="text-xs text-zinc-400">
                Sign in to unlock your local keystore & P2P channels
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

          <form onSubmit={handleLogin} className="mt-6 space-y-4" noValidate>
            <div>
              <label
                htmlFor="login-email"
                className="block text-xs font-medium text-zinc-300"
              >
                Email Address
              </label>
              <input
                id="login-email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@ciphermesh.sec"
                className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 transition-colors focus:border-violet-500 focus:outline-none"
              />
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label
                  htmlFor="login-password"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Password
                </label>
                <Link
                  href="/reset-password"
                  className="text-xs text-violet-400 hover:text-violet-300"
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative mt-1.5">
                <input
                  id="login-password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg border border-white/10 bg-[#090a0f] py-2.5 pr-10 pl-3.5 text-sm text-white placeholder-zinc-600 transition-colors focus:border-violet-500 focus:outline-none"
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

            <button
              type="submit"
              disabled={loading}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Unlocking Local Keystore...</span>
                </>
              ) : (
                <>
                  <Lock className="h-4 w-4" />
                  <span>Sign In to CipherMesh</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 border-t border-white/[0.075] pt-4">
            <div className="flex items-center justify-between font-mono text-[11px] text-zinc-500">
              <span>KEYSTORE BOUNDARY</span>
              <span className="text-emerald-400">CLIENT-SIDE ONLY</span>
            </div>
            <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-500">
              Your Ed25519 and X25519 private keys are stored in your local
              browser IndexedDB and never transmitted during sign-in.
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
