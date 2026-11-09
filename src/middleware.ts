import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Lightweight in-memory rate-limiting tracker for auth/API endpoints
const ipRequestCounts = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;

export function middleware(request: NextRequest) {
  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "127.0.0.1";
  const now = Date.now();
  const entry = ipRequestCounts.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    ipRequestCounts.set(ip, { count: 1, windowStart: now });
  } else {
    entry.count += 1;
    if (entry.count > MAX_REQUESTS_PER_WINDOW) {
      return new NextResponse(
        JSON.stringify({
          error: "Too many requests. Rate limit enforced by CipherMesh edge guard.",
        }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": "60",
          },
        }
      );
    }
  }

  const response = NextResponse.next();
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
