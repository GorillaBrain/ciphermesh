"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Shield,
  KeyRound,
  AlertCircle,
  CheckCircle2,
  ArrowLeft,
  Loader2,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";

export default function ResetPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function handleReset(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !email.includes("@")) {
      setError("Please enter a valid registered email address.");
      return;
    }

    setLoading(true);
    try {
      const supabase = createClient();
      const redirectUrl =
        typeof window !== "undefined"
          ? `${window.location.origin}/login`
          : undefined;
      const { error: resetErr } = await supabase.auth.resetPasswordForEmail(
        email.trim().toLowerCase(),
        { redirectTo: redirectUrl }
      );
      if (resetErr) {
        setError(resetErr.message);
      } else {
        setSent(true);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to initiate password recovery."
      );
    } finally {
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
            className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Back to Sign In</span>
          </Link>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center px-4 py-12">
        <div className="rounded-xl border border-white/10 bg-[#11131a] p-6 sm:p-8">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-400">
              <KeyRound className="h-4 w-4" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">
                Account Password Recovery
              </h1>
              <p className="text-xs text-zinc-400">
                Reset your authentication credentials
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

          {sent ? (
            <div className="mt-6 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200">
              <div className="flex items-center gap-2 font-semibold text-emerald-400">
                <CheckCircle2 className="h-4 w-4" />
                <span>Recovery Instructions Dispatched</span>
              </div>
              <p className="mt-2 leading-relaxed">
                If an account exists for <span className="font-mono">{email}</span>,
                a recovery link has been sent. Note: Password recovery resets
                account authentication, but cannot recover private keys stored
                exclusively on a lost device.
              </p>
              <Link
                href="/login"
                className="mt-4 inline-flex items-center gap-1.5 font-medium text-violet-400 hover:text-violet-300"
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                <span>Return to Sign In</span>
              </Link>
            </div>
          ) : (
            <form onSubmit={handleReset} className="mt-6 space-y-4" noValidate>
              <div>
                <label
                  htmlFor="reset-email"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Registered Email Address
                </label>
                <input
                  id="reset-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@ciphermesh.sec"
                  className="mt-1.5 w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 focus:border-violet-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-violet-500 disabled:opacity-60"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Sending Recovery Link...</span>
                  </>
                ) : (
                  <span>Send Recovery Instructions</span>
                )}
              </button>
            </form>
          )}

          <div className="mt-6 border-t border-white/[0.075] pt-4 text-[11px] leading-relaxed text-zinc-500">
            <strong className="text-zinc-400">Cryptographic Notice:</strong>{" "}
            Because CipherMesh never stores private keys on its servers,
            signing in from a new device after password recovery will provision
            a new device keypair and notify your contacts of an identity key
            change.
          </div>
        </div>
      </main>

      <footer className="border-t border-white/[0.075] py-5 text-center font-mono text-xs text-zinc-600">
        CipherMesh — Private by Architecture.
      </footer>
    </div>
  );
}
