# CipherMesh — Security Hardening & Verification (`SECURITY.md`)

---

## 1. Application & Transport Hardening

1. **HTTP Security Headers & Content Security Policy (`next.config.ts` & `src/middleware.ts`):**
   - `Content-Security-Policy`: Restricts `default-src 'self'`, `connect-src 'self' https://*.supabase.co wss://*.supabase.co`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`.
   - `Strict-Transport-Security`: `max-age=63072000; includeSubDomains; preload`
   - `X-Frame-Options`: `DENY`
   - `X-Content-Type-Options`: `nosniff`
   - `Referrer-Policy`: `strict-origin-when-cross-origin`
   - `Permissions-Policy`: Disables microphone, geolocation, and FLoC/interest-cohort; scopes camera to `(self)`.
2. **Edge Rate Limiting (`src/middleware.ts`):**
   - Enforces per-IP sliding window rate limits with HTTP `429 Too Many Requests` and `Retry-After` headers.
3. **Zero Secret Exposure:**
   - Only public anon/publishable keys (`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`) are used by the client; all authorization is enforced via PostgreSQL Row Level Security (RLS) tied to authenticated JWTs.
   - `.gitignore` blocks `.env*` files (except `.env.example`).
4. **Safe File Handling:**
   - Transferred files are processed as raw `Uint8Array` buffers, encrypted chunk-by-chunk with `XChaCha20-Poly1305`, verified against a whole-file `SHA-256` manifest digest prior to reassembly, and downloaded via `Content-Disposition` blob links rather than executed inline.

---

## 2. Automated Security Verification Suite

Run the full automated verification suite with:

```bash
# Unit & Live Supabase RLS / Cryptographic Tamper Tests
npm test

# Multi-Browser Playwright End-to-End Verification
npm run test:e2e
```
