# CipherMesh — Production Deployment Guide (`DEPLOYMENT.md`)

CipherMesh is designed for serverless frontend hosting on **Vercel** paired with **Supabase** (PostgreSQL + Auth + Realtime Broadcast) and **WebRTC DataChannels** (STUN/TURN).

---

## 1. Why This Architecture Fits Vercel's Execution Model

Vercel serverless functions are stateless and do not host persistent raw UDP/TCP TURN relays or stateful WebSocket brokers. CipherMesh solves this cleanly:
- **WebRTC Signaling & Presence:** Handled via Supabase Realtime WebSocket channels (`ciphermesh-signal:<conversationId>` and `ciphermesh-global-presence`).
- **Direct Peer-to-Peer Data Path:** Once ICE negotiation succeeds, encrypted messages and file chunks flow directly between browsers over `RTCDataChannel` (`ciphermesh-e2ee-v1`).
- **Asynchronous Offline Delivery:** Persisted as authenticated `XChaCha20-Poly1305` ciphertexts in Supabase PostgreSQL (`public.encrypted_messages`).

---

## 2. Environment Variables

Configure the following environment variables in Vercel (`Settings → Environment Variables`) and locally in `.env.local`:

| Variable | Description | Required |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase Project URL (`https://<ref>.supabase.co`) | Yes |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Supabase Anon / Publishable Key (RLS-enforced) | Yes |
| `NEXT_PUBLIC_APP_URL` | Production URL (e.g. `https://ciphermesh.vercel.app`) | Yes |
| `NEXT_PUBLIC_ICE_SERVERS` | JSON array of STUN/TURN `RTCIceServer` objects | Optional (Defaults to Google & Cloudflare STUN) |

### Configuring Production TURN Relays
For peers behind strict symmetric NATs where STUN hole-punching cannot establish a direct P2P path, provide a standards-compliant TURN server (e.g., Cloudflare Calls TURN, Metered.ca, or coturn) in `NEXT_PUBLIC_ICE_SERVERS`:

```json
[
  {"urls": "stun:stun.cloudflare.com:3478"},
  {
    "urls": ["turn:turn.example.com:3478?transport=udp", "turns:turn.example.com:5349?transport=tcp"],
    "username": "turn_user",
    "credential": "turn_password"
  }
]
```

Even without a TURN server, CipherMesh automatically falls back to encrypted store-and-forward delivery so communication is never interrupted.
