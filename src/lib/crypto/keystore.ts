/**
 * Client-Side Cryptographic KeyStore
 *
 * Stores device identity keypairs (Ed25519 + X25519) strictly on the client
 * inside IndexedDB (`ciphermesh_keystore_v1`), with mirrored fallback in localStorage
 * scoped by authenticated `userId`.
 *
 * Private keys (`ed25519SecretKeyHex`, `x25519SecretKeyHex`) are NEVER sent to the server.
 */

import {
  DeviceIdentityBundle,
  generateDeviceIdentity,
  verifyKeyBindingSignature,
} from "./engine";

const DB_NAME = "ciphermesh_keystore_v1";
const STORE_NAME = "device_identities";
const LS_PREFIX = "ciphermesh:device_identity:";

function getBrowserDeviceLabel(): string {
  if (typeof navigator === "undefined") return "Workstation Node";
  const ua = navigator.userAgent;
  let browser = "Browser";
  if (ua.includes("Edg/")) browser = "Edge";
  else if (ua.includes("Chrome/")) browser = "Chrome";
  else if (ua.includes("Firefox/")) browser = "Firefox";
  else if (ua.includes("Safari/")) browser = "Safari";

  let os = "Desktop";
  if (ua.includes("Win")) os = "Windows";
  else if (ua.includes("Mac")) os = "macOS";
  else if (ua.includes("Linux")) os = "Linux";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";

  return `${browser} on ${os}`;
}

function openKeyStoreDB(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === "undefined") {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "userId" });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function loadLocalDeviceIdentity(
  userId: string
): Promise<DeviceIdentityBundle | null> {
  // 1. Try IndexedDB
  const db = await openKeyStoreDB();
  if (db) {
    const record = await new Promise<DeviceIdentityBundle | null>((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);
        const getReq = store.get(userId);
        getReq.onsuccess = () => {
          resolve(getReq.result?.bundle ?? null);
        };
        getReq.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
    if (
      record &&
      verifyKeyBindingSignature(
        record.ed25519PublicKeyHex,
        record.x25519PublicKeyHex,
        record.keySignatureHex,
        record.keyVersion
      )
    ) {
      return record;
    }
  }

  // 2. Fallback to localStorage
  if (typeof localStorage !== "undefined") {
    try {
      const raw = localStorage.getItem(`${LS_PREFIX}${userId}`);
      if (raw) {
        const parsed = JSON.parse(raw) as DeviceIdentityBundle;
        if (
          verifyKeyBindingSignature(
            parsed.ed25519PublicKeyHex,
            parsed.x25519PublicKeyHex,
            parsed.keySignatureHex,
            parsed.keyVersion
          )
        ) {
          return parsed;
        }
      }
    } catch {
      // ignore corrupted storage
    }
  }

  return null;
}

export async function saveLocalDeviceIdentity(
  userId: string,
  bundle: DeviceIdentityBundle
): Promise<void> {
  const db = await openKeyStoreDB();
  if (db) {
    await new Promise<void>((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const store = tx.objectStore(STORE_NAME);
        store.put({ userId, bundle });
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      } catch {
        resolve();
      }
    });
  }

  if (typeof localStorage !== "undefined") {
    try {
      localStorage.setItem(`${LS_PREFIX}${userId}`, JSON.stringify(bundle));
    } catch {
      // ignore quota errors
    }
  }
}

export async function getOrCreateLocalDeviceIdentity(
  userId: string,
  customLabel?: string
): Promise<{ bundle: DeviceIdentityBundle; isNewlyGenerated: boolean }> {
  const existing = await loadLocalDeviceIdentity(userId);
  if (existing) {
    return { bundle: existing, isNewlyGenerated: false };
  }

  const label = customLabel || getBrowserDeviceLabel();
  const fresh = generateDeviceIdentity(label, 1);
  await saveLocalDeviceIdentity(userId, fresh);
  return { bundle: fresh, isNewlyGenerated: true };
}

export async function rotateLocalDeviceIdentityKeys(
  userId: string
): Promise<DeviceIdentityBundle> {
  const existing = await loadLocalDeviceIdentity(userId);
  const nextVersion = existing ? existing.keyVersion + 1 : 1;
  const label = existing?.deviceLabel || getBrowserDeviceLabel();
  const rotated = generateDeviceIdentity(
    label,
    nextVersion,
    existing?.deviceId
  );
  await saveLocalDeviceIdentity(userId, rotated);
  return rotated;
}

export async function clearLocalDeviceIdentity(userId: string): Promise<void> {
  const db = await openKeyStoreDB();
  if (db) {
    await new Promise<void>((resolve) => {
      try {
        const tx = db.transaction(STORE_NAME, "readwrite");
        tx.objectStore(STORE_NAME).delete(userId);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      } catch {
        resolve();
      }
    });
  }
  if (typeof localStorage !== "undefined") {
    localStorage.removeItem(`${LS_PREFIX}${userId}`);
  }
}
