import { NextResponse } from "next/server";
import { CIPHERMESH_ALGORITHM_SUITE, CIPHERMESH_PROTOCOL_VERSION } from "@/lib/crypto/engine";

export async function GET() {
  return NextResponse.json(
    {
      status: "healthy",
      service: "CipherMesh E2EE P2P Platform",
      protocolVersion: CIPHERMESH_PROTOCOL_VERSION,
      cipherSuite: CIPHERMESH_ALGORITHM_SUITE,
      zeroPlaintextStorage: true,
      timestamp: new Date().toISOString(),
    },
    { status: 200 }
  );
}
