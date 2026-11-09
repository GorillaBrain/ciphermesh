import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CipherMesh — Private by Architecture | E2EE P2P Communication Platform",
  description:
    "A peer-to-peer communication platform engineered around application-layer end-to-end encryption (X25519, HKDF-SHA256, XChaCha20-Poly1305, Ed25519), cryptographic device verification, and privacy by design.",
  keywords: [
    "CipherMesh",
    "End-to-End Encryption",
    "WebRTC P2P",
    "XChaCha20-Poly1305",
    "X25519",
    "Ed25519",
    "Zero-Knowledge Messaging",
    "Cybersecurity",
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[#090a0f] text-[#f3f4f6]">
        {children}
      </body>
    </html>
  );
}
