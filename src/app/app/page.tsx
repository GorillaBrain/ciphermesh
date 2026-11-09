"use client";

import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Search,
  Plus,
  MessageSquare,
  Settings,
  LogOut,
  Send,
  Paperclip,
  Clock,
  Reply,
  Trash2,
  Check,
  CheckCheck,
  Radio,
  PanelRightClose,
  PanelRightOpen,
  FileText,
  Download,
  Pause,
  Play,
  X,
  AlertTriangle,
  RefreshCw,
  ArrowLeft,
  Loader2,
  UserPlus,
  Eye,
} from "lucide-react";
import { createClient } from "@/lib/supabase/client";
import {
  ensureDeviceRegisteredWithBackend,
  rotateAndPublishDeviceKeys,
} from "@/lib/crypto/device-sync";
import {
  type DeviceIdentityBundle,
  type PlaintextMessagePayload,
  type EncryptedFileChunk,
  encryptMessageForPeer,
  decryptMessageEnvelope,
  ReplayProtectionWindow,
  splitAndEncryptFile,
  decryptAndReassembleFile,
  deriveSessionIdentifier,
} from "@/lib/crypto/engine";
import {
  CipherMeshPeerSession,
  type WebRTCConnectionTelemetry,
  type P2PWirePacket,
} from "@/lib/webrtc/peer-manager";
import type {
  UserProfile,
  DeviceRecord,
  ConversationRecord,
  EncryptedMessageRecord,
  MessageReceiptRecord,
  ContactVerificationRecord,
  SecurityEventRecord,
  UserPreferencesRecord,
} from "@/types/ciphermesh";
import { SecurityCenterView } from "@/components/security/SecurityCenterView";
import { ContactSecuritySidebar } from "@/components/chat/ContactSecuritySidebar";
import { SettingsView } from "@/components/settings/SettingsView";

interface DecryptedChatMessage {
  record: EncryptedMessageRecord;
  plaintext: PlaintextMessagePayload | null;
  decryptionError: string | null;
  receiptStatus: "sent" | "delivered" | "read";
}

interface ActiveFileTransfer {
  transferId: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  sha256Hash: string;
  totalChunks: number;
  receivedChunks: EncryptedFileChunk[];
  direction: "outgoing" | "incoming";
  status: "transferring" | "paused" | "completed" | "cancelled" | "failed";
  reassembledBytes?: Uint8Array;
  error?: string;
}

interface ConversationListItem {
  conversation: ConversationRecord;
  peer: UserProfile;
  unreadCount: number;
  lastMessageAt: string;
  lastSnippet: string;
}

const EPHEMERAL_OPTIONS: { label: string; value: number | null }[] = [
  { label: "Off", value: null },
  { label: "30s", value: 30 },
  { label: "1m", value: 60 },
  { label: "5m", value: 300 },
  { label: "1h", value: 3600 },
  { label: "24h", value: 86400 },
];

export default function CipherMeshWorkspacePage() {
  const router = useRouter();
  const supabase = useMemo(() => createClient(), []);

  // Core Auth & Identity State
  const [loadingInitial, setLoadingInitial] = useState(true);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  const [localDevice, setLocalDevice] = useState<DeviceIdentityBundle | null>(
    null
  );
  const [myDevices, setMyDevices] = useState<DeviceRecord[]>([]);
  const [preferences, setPreferences] = useState<UserPreferencesRecord>({
    user_id: "",
    auto_key_rotation_messages: 50,
    default_ephemeral_ttl: null,
    require_verified_for_files: false,
    allow_turn_relay: true,
    force_turn_relay: false,
    show_typing_indicators: true,
    show_read_receipts: true,
    max_file_size_mb: 25,
    updated_at: new Date().toISOString(),
  });

  // Navigation & Responsive Panels
  const [activeTab, setActiveTab] = useState<
    "messages" | "security" | "settings"
  >("messages");
  const [showRightInspector, setShowRightInspector] = useState(true);
  const [mobileShowChat, setMobileShowChat] = useState(false);

  // Directory & Conversations
  const [allProfiles, setAllProfiles] = useState<UserProfile[]>([]);
  const [allDevicesByUser, setAllDevicesByUser] = useState<
    Record<string, DeviceRecord[]>
  >({});
  const [conversations, setConversations] = useState<ConversationListItem[]>(
    []
  );
  const [activeConversationId, setActiveConversationId] = useState<
    string | null
  >(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showNewConversationModal, setShowNewConversationModal] =
    useState(false);
  const [newConvSearch, setNewConvSearch] = useState("");

  // Active Chat State
  const [encryptedMessages, setEncryptedMessages] = useState<
    EncryptedMessageRecord[]
  >([]);
  const [receiptsByMessage, setReceiptsByMessage] = useState<
    Record<string, MessageReceiptRecord[]>
  >({});
  const [composerText, setComposerText] = useState("");
  const [replyingTo, setReplyingTo] = useState<{
    id: string;
    senderName: string;
    snippet: string;
  } | null>(null);
  const [sendingMessage, setSendingMessage] = useState(false);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [fileTransfers, setFileTransfers] = useState<
    Record<string, ActiveFileTransfer>
  >({});
  const [inspectingEnvelopeMsg, setInspectingEnvelopeMsg] =
    useState<EncryptedMessageRecord | null>(null);

  // Real-time Presence, Typing & WebRTC Telemetry
  const [onlineUserIds, setOnlineUserIds] = useState<Set<string>>(new Set());
  const [peerIsTyping, setPeerIsTyping] = useState(false);
  const [webrtcTelemetry, setWebrtcTelemetry] =
    useState<WebRTCConnectionTelemetry | null>(null);

  // Verification & Security Events
  const [verifications, setVerifications] = useState<
    ContactVerificationRecord[]
  >([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEventRecord[]>(
    []
  );
  const [identityChangedPeers, setIdentityChangedPeers] = useState<
    Record<string, string>
  >({});
  const [nowTick, setNowTick] = useState<number>(() => Date.now());

  // Refs for WebRTC Session, Replay Protection, and Outgoing File Control
  const peerSessionRef = useRef<CipherMeshPeerSession | null>(null);
  const replayWindowRef = useRef<ReplayProtectionWindow>(
    new ReplayProtectionWindow(4096)
  );
  const outgoingTransferControlRef = useRef<
    Record<string, { paused: boolean; cancelled: boolean }>
  >({});
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Derived active conversation & peer
  const activeConversationItem = useMemo(
    () =>
      conversations.find(
        (c) => c.conversation.id === activeConversationId
      ) ?? null,
    [conversations, activeConversationId]
  );

  const activePeer = activeConversationItem?.peer ?? null;
  const activePeerDevices = useMemo(
    () => (activePeer ? allDevicesByUser[activePeer.id] ?? [] : []),
    [activePeer, allDevicesByUser]
  );
  const activePeerPrimaryDevice = useMemo(
    () =>
      activePeerDevices.find((d) => !d.is_revoked) ??
      activePeerDevices[0] ??
      null,
    [activePeerDevices]
  );

  // Ephemeral message ticker (runs every 1 second to prune expired messages seamlessly)
  useEffect(() => {
    const timer = setInterval(() => {
      setNowTick(Date.now());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Load all conversations, profiles, devices, verifications, and security events
  const refreshWorkspaceData = useCallback(
    async (uid: string) => {
      const [
        profilesRes,
        devicesRes,
        membershipsRes,
        verificationsRes,
        eventsRes,
        prefsRes,
      ] = await Promise.all([
        supabase.from("profiles").select("*").order("username"),
        supabase
          .from("devices")
          .select("*")
          .order("last_active_at", { ascending: false }),
        supabase
          .from("conversation_members")
          .select("conversation_id, user_id, last_read_at")
          .eq("user_id", uid),
        supabase
          .from("contact_verifications")
          .select("*")
          .eq("verifier_user_id", uid),
        supabase
          .from("security_events")
          .select("*")
          .eq("user_id", uid)
          .order("created_at", { ascending: false })
          .limit(50),
        supabase
          .from("user_preferences")
          .select("*")
          .eq("user_id", uid)
          .maybeSingle(),
      ]);

      const profilesList = (profilesRes.data ?? []) as UserProfile[];
      setAllProfiles(profilesList);
      const profileMap = new Map(profilesList.map((p) => [p.id, p]));

      const me = profileMap.get(uid);
      if (me) setCurrentUser(me);

      const devicesList = (devicesRes.data ?? []) as DeviceRecord[];
      const groupedDevices: Record<string, DeviceRecord[]> = {};
      for (const d of devicesList) {
        if (!groupedDevices[d.user_id]) groupedDevices[d.user_id] = [];
        groupedDevices[d.user_id].push(d);
      }
      setAllDevicesByUser(groupedDevices);
      setMyDevices(groupedDevices[uid] ?? []);

      const verifList = (verificationsRes.data ??
        []) as ContactVerificationRecord[];
      setVerifications(verifList);

      // Check if any previously verified contact now has a different active device fingerprint
      const changedMap: Record<string, string> = {};
      for (const v of verifList) {
        const peerDevs = groupedDevices[v.contact_user_id] ?? [];
        const currentPrimary = peerDevs.find((d) => !d.is_revoked);
        if (
          currentPrimary &&
          currentPrimary.fingerprint !== v.verified_fingerprint &&
          !peerDevs.some(
            (d) => !d.is_revoked && d.fingerprint === v.verified_fingerprint
          )
        ) {
          changedMap[v.contact_user_id] = v.verified_fingerprint;
        }
      }
      setIdentityChangedPeers(changedMap);

      if (eventsRes.data) {
        setSecurityEvents(eventsRes.data as SecurityEventRecord[]);
      }
      if (prefsRes.data) {
        setPreferences(prefsRes.data as UserPreferencesRecord);
      }

      // Build conversation list
      const myMemberships = membershipsRes.data ?? [];
      if (myMemberships.length > 0) {
        const convIds = myMemberships.map((m) => m.conversation_id);
        const [convsRes, allMembersRes, latestMsgsRes] = await Promise.all([
          supabase.from("conversations").select("*").in("id", convIds),
          supabase
            .from("conversation_members")
            .select("conversation_id, user_id, last_read_at")
            .in("conversation_id", convIds),
          supabase
            .from("encrypted_messages")
            .select("id, conversation_id, sender_id, created_at, expires_at, is_deleted")
            .in("conversation_id", convIds)
            .order("created_at", { ascending: false }),
        ]);

        const convMap = new Map(
          ((convsRes.data ?? []) as ConversationRecord[]).map((c) => [c.id, c])
        );
        const myReadMap = new Map(
          myMemberships.map((m) => [m.conversation_id, m.last_read_at])
        );

        const items: ConversationListItem[] = [];
        for (const convId of convIds) {
          const conv = convMap.get(convId);
          if (!conv) continue;
          const otherMember = (allMembersRes.data ?? []).find(
            (m) => m.conversation_id === convId && m.user_id !== uid
          );
          if (!otherMember) continue;
          const peer = profileMap.get(otherMember.user_id);
          if (!peer) continue;

          const myLastRead = myReadMap.get(convId) ?? conv.created_at;
          const convMsgs = (latestMsgsRes.data ?? []).filter(
            (m) =>
              m.conversation_id === convId &&
              !m.is_deleted &&
              (!m.expires_at || new Date(m.expires_at).getTime() > Date.now())
          );

          const unreadCount = convMsgs.filter(
            (m) =>
              m.sender_id !== uid &&
              new Date(m.created_at).getTime() > new Date(myLastRead).getTime()
          ).length;

          const newestMsg = convMsgs[0];
          items.push({
            conversation: conv,
            peer,
            unreadCount,
            lastMessageAt: newestMsg?.created_at ?? conv.updated_at,
            lastSnippet: newestMsg
              ? "Encrypted XChaCha20-Poly1305 Envelope"
              : "Session ready — No messages yet",
          });
        }

        items.sort(
          (a, b) =>
            new Date(b.lastMessageAt).getTime() -
            new Date(a.lastMessageAt).getTime()
        );
        setConversations(items);
      } else {
        setConversations([]);
      }
    },
    [supabase]
  );

  // Initialize authenticated user & local keystore
  useEffect(() => {
    let mounted = true;

    async function init() {
      const {
        data: { user },
      } = await supabase.auth.getUser();

      if (!user) {
        router.replace("/login");
        return;
      }

      const bundle = await ensureDeviceRegisteredWithBackend(supabase, user.id);
      if (!mounted) return;
      setLocalDevice(bundle);

      await refreshWorkspaceData(user.id);
      if (mounted) setLoadingInitial(false);
    }

    void init();
    return () => {
      mounted = false;
    };
  }, [supabase, router, refreshWorkspaceData]);

  // Global Presence & Database Realtime Subscriptions
  useEffect(() => {
    if (!currentUser) return;

    const presenceChannel = supabase.channel("ciphermesh-global-presence", {
      config: {
        presence: { key: currentUser.id },
      },
    });

    presenceChannel
      .on("presence", { event: "sync" }, () => {
        const state = presenceChannel.presenceState();
        setOnlineUserIds(new Set(Object.keys(state)));
      })
      .subscribe(async (status) => {
        if (status === "SUBSCRIBED") {
          await presenceChannel.track({
            user_id: currentUser.id,
            username: currentUser.username,
            online_at: new Date().toISOString(),
          });
        }
      });

    const dbChannel = supabase
      .channel(`ciphermesh-db-sync:${currentUser.id}`)
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "encrypted_messages" },
        (payload) => {
          const rec = (payload.new || payload.old) as EncryptedMessageRecord;
          if (payload.eventType === "INSERT" && payload.new) {
            const newMsg = payload.new as EncryptedMessageRecord;
            if (newMsg.conversation_id === activeConversationId) {
              setEncryptedMessages((prev) =>
                prev.some((m) => m.id === newMsg.id) ? prev : [...prev, newMsg]
              );
            }
            void refreshWorkspaceData(currentUser.id);
          } else if (payload.eventType === "UPDATE" && payload.new) {
            const updatedMsg = payload.new as EncryptedMessageRecord;
            if (updatedMsg.conversation_id === activeConversationId) {
              setEncryptedMessages((prev) =>
                prev.map((m) => (m.id === updatedMsg.id ? updatedMsg : m))
              );
            }
          } else if (payload.eventType === "DELETE" && rec) {
            setEncryptedMessages((prev) =>
              prev.filter((m) => m.id !== rec.id)
            );
          }
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "message_receipts" },
        (payload) => {
          if (payload.new) {
            const r = payload.new as MessageReceiptRecord;
            setReceiptsByMessage((prev) => {
              const existing = prev[r.message_id] ?? [];
              const filtered = existing.filter(
                (item) => item.recipient_id !== r.recipient_id
              );
              return { ...prev, [r.message_id]: [...filtered, r] };
            });
          }
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "profiles" },
        () => {
          void refreshWorkspaceData(currentUser.id);
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "devices" },
        () => {
          void refreshWorkspaceData(currentUser.id);
        }
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "conversations" },
        () => {
          void refreshWorkspaceData(currentUser.id);
        }
      )
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "security_events",
          filter: `user_id=eq.${currentUser.id}`,
        },
        (payload) => {
          if (payload.new) {
            const ev = payload.new as SecurityEventRecord;
            setSecurityEvents((prev) =>
              prev.some((e) => e.id === ev.id) ? prev : [ev, ...prev]
            );
          }
        }
      )
      .subscribe();

    return () => {
      void supabase.removeChannel(presenceChannel);
      void supabase.removeChannel(dbChannel);
    };
  }, [currentUser, activeConversationId, supabase, refreshWorkspaceData]);

  // Load Active Conversation Messages & Establish WebRTC P2P Session
  useEffect(() => {
    if (!currentUser || !activeConversationId || !activePeer || !localDevice) {
      if (peerSessionRef.current) {
        peerSessionRef.current.destroy();
        peerSessionRef.current = null;
      }
      setWebrtcTelemetry(null);
      return;
    }

    let cancelled = false;
    replayWindowRef.current.reset();

    async function loadConversationMessages() {
      const [msgsRes, receiptsRes] = await Promise.all([
        supabase
          .from("encrypted_messages")
          .select("*")
          .eq("conversation_id", activeConversationId)
          .order("created_at", { ascending: true }),
        supabase
          .from("message_receipts")
          .select("*")
          .eq("conversation_id", activeConversationId),
      ]);

      if (cancelled) return;

      const msgs = (msgsRes.data ?? []) as EncryptedMessageRecord[];
      setEncryptedMessages(msgs);

      const receiptGrouped: Record<string, MessageReceiptRecord[]> = {};
      for (const r of (receiptsRes.data ?? []) as MessageReceiptRecord[]) {
        if (!receiptGrouped[r.message_id]) receiptGrouped[r.message_id] = [];
        receiptGrouped[r.message_id].push(r);
      }
      setReceiptsByMessage(receiptGrouped);

      // Update last_read_at for unread counter
      await supabase
        .from("conversation_members")
        .update({ last_read_at: new Date().toISOString() })
        .eq("conversation_id", activeConversationId)
        .eq("user_id", currentUser!.id);

      // Mark incoming messages as read if preference enabled
      if (preferences.show_read_receipts) {
        const incomingIds = msgs
          .filter((m) => m.sender_id !== currentUser!.id && !m.is_deleted)
          .map((m) => m.id);

        for (const msgId of incomingIds) {
          const alreadyRead = receiptGrouped[msgId]?.some(
            (r) => r.recipient_id === currentUser!.id && r.status === "read"
          );
          if (!alreadyRead) {
            await supabase.from("message_receipts").upsert(
              {
                message_id: msgId,
                conversation_id: activeConversationId,
                recipient_id: currentUser!.id,
                recipient_device_id: localDevice?.deviceId ?? null,
                status: "read",
                updated_at: new Date().toISOString(),
              },
              { onConflict: "message_id,recipient_id" }
            );
          }
        }
      }

      void refreshWorkspaceData(currentUser!.id);
    }

    void loadConversationMessages();

    // Start WebRTC P2P Session
    if (peerSessionRef.current) {
      peerSessionRef.current.destroy();
    }

    const session = new CipherMeshPeerSession({
      supabase,
      conversationId: activeConversationId,
      myUserId: currentUser.id,
      peerUserId: activePeer.id,
      forceTurnRelay: preferences.force_turn_relay,
      onTelemetryChange: (t) => {
        if (!cancelled) setWebrtcTelemetry({ ...t });
      },
      onWirePacket: (packet) => {
        if (cancelled) return;
        handleIncomingWirePacket(packet);
      },
    });

    peerSessionRef.current = session;
    void session.start();

    return () => {
      cancelled = true;
      session.destroy();
      if (peerSessionRef.current === session) {
        peerSessionRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    currentUser?.id,
    activeConversationId,
    activePeer?.id,
    localDevice?.fingerprint,
    preferences.force_turn_relay,
  ]);

  // Handle Incoming WebRTC P2P Wire Packets (Typing, Receipts, Chunked File Transfers, Session Control)
  function handleIncomingWirePacket(packet: P2PWirePacket) {
    if (!currentUser || !localDevice) return;

    if (packet.type === "typing_signal") {
      setPeerIsTyping(Boolean(packet.isTyping));
      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      if (packet.isTyping) {
        typingTimeoutRef.current = setTimeout(() => {
          setPeerIsTyping(false);
        }, 3500);
      }
    } else if (packet.type === "file_control" && packet.fileControl) {
      const fc = packet.fileControl;
      setFileTransfers((prev) => {
        const existing = prev[fc.transferId];
        if (fc.action === "cancel") {
          if (outgoingTransferControlRef.current[fc.transferId]) {
            outgoingTransferControlRef.current[fc.transferId].cancelled = true;
          }
          return existing
            ? {
                ...prev,
                [fc.transferId]: { ...existing, status: "cancelled" },
              }
            : prev;
        }
        if (fc.action === "pause" && existing) {
          return {
            ...prev,
            [fc.transferId]: { ...existing, status: "paused" },
          };
        }
        if (fc.action === "resume" && existing) {
          return {
            ...prev,
            [fc.transferId]: { ...existing, status: "transferring" },
          };
        }
        return prev;
      });
    } else if (packet.type === "file_chunk" && packet.fileChunk) {
      const chunk = packet.fileChunk;
      setFileTransfers((prev) => {
        const current = prev[chunk.transferId] ?? {
          transferId: chunk.transferId,
          fileName: "Encrypted File Stream",
          fileSize: 0,
          mimeType: "application/octet-stream",
          sha256Hash: "",
          totalChunks: chunk.totalChunks,
          receivedChunks: [],
          direction: "incoming",
          status: "transferring",
        };

        if (current.status === "cancelled") return prev;

        const alreadyHas = current.receivedChunks.some(
          (c) => c.chunkIndex === chunk.chunkIndex
        );
        const updatedChunks = alreadyHas
          ? current.receivedChunks
          : [...current.receivedChunks, chunk];

        const isAllReceived = updatedChunks.length >= chunk.totalChunks;

        return {
          ...prev,
          [chunk.transferId]: {
            ...current,
            receivedChunks: updatedChunks,
            status: isAllReceived ? "completed" : current.status,
          },
        };
      });
    } else if (packet.type === "encrypted_message" && packet.envelope) {
      // Immediately append incoming P2P encrypted message if not already in state, and trigger background DB sync
      void supabase
        .from("encrypted_messages")
        .select("*")
        .eq("conversation_id", packet.conversationId)
        .order("created_at", { ascending: true })
        .then(({ data }) => {
          if (data) {
            setEncryptedMessages(data as EncryptedMessageRecord[]);
          }
        });
    } else if (packet.type === "session_control" && packet.sessionControl) {
      void refreshWorkspaceData(currentUser.id);
    }
  }

  // Decrypt and verify messages in active conversation
  const decryptedMessages: DecryptedChatMessage[] = useMemo(() => {
    if (!currentUser || !localDevice || !activeConversationId) return [];

    return encryptedMessages
      .filter((msg) => {
        if (msg.is_deleted) return false;
        if (msg.expires_at && new Date(msg.expires_at).getTime() <= nowTick) {
          return false;
        }
        return true;
      })
      .map((record) => {
        const isOutgoing = record.sender_id === currentUser.id;
        // Determine peer X25519 public key for ECDH shared secret derivation
        const peerX25519Pub = isOutgoing
          ? activePeerPrimaryDevice?.x25519_public_key ?? ""
          : record.sender_x25519_public_key;

        let plaintext: PlaintextMessagePayload | null = null;
        let decryptionError: string | null = null;

        if (!peerX25519Pub) {
          decryptionError =
            "Waiting for peer device public key registration...";
        } else {
          try {
            plaintext = decryptMessageEnvelope({
              envelope: {
                ciphertext: record.ciphertext,
                nonce: record.nonce,
                ephemeralPublicKey: record.ephemeral_public_key,
                senderEd25519PublicKey: record.sender_ed25519_public_key,
                senderX25519PublicKey: record.sender_x25519_public_key,
                signature: record.signature,
                sequenceNumber: Number(record.sequence_number),
                sessionEpoch: record.session_epoch,
                algorithm: record.algorithm,
              },
              conversationId: record.conversation_id,
              myX25519SecretKeyHex: localDevice.x25519SecretKeyHex,
              peerX25519PublicKeyHex: peerX25519Pub,
            });
          } catch (err) {
            decryptionError =
              err instanceof Error
                ? err.message
                : "Decryption or signature verification failed";
          }
        }

        const msgReceipts = receiptsByMessage[record.id] ?? [];
        const hasRead = msgReceipts.some((r) => r.status === "read");
        const hasDelivered = msgReceipts.some(
          (r) => r.status === "delivered" || r.status === "read"
        );

        return {
          record,
          plaintext,
          decryptionError,
          receiptStatus: hasRead
            ? "read"
            : hasDelivered
              ? "delivered"
              : "sent",
        };
      });
  }, [
    encryptedMessages,
    currentUser,
    localDevice,
    activeConversationId,
    activePeerPrimaryDevice,
    receiptsByMessage,
    nowTick,
  ]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [decryptedMessages.length, activeConversationId]);

  // Create or open a 1-on-1 conversation with a user
  async function handleStartOrSelectConversation(peerProfile: UserProfile) {
    if (!currentUser) return;
    setShowNewConversationModal(false);

    const { data: convId, error } = await supabase.rpc(
      "get_or_create_direct_conversation",
      { peer_id: peerProfile.id }
    );

    if (!error && convId) {
      await refreshWorkspaceData(currentUser.id);
      setActiveConversationId(convId as string);
      setActiveTab("messages");
      setMobileShowChat(true);
    }
  }

  // Send Encrypted Message
  async function handleSendMessage(e?: React.FormEvent) {
    if (e) e.preventDefault();
    if (
      !composerText.trim() ||
      !currentUser ||
      !localDevice ||
      !activeConversationItem ||
      !activePeerPrimaryDevice ||
      sendingMessage
    ) {
      return;
    }

    const textToSend = composerText.trim();
    setComposerText("");
    const replySnapshot = replyingTo;
    setReplyingTo(null);
    setSendingMessage(true);

    try {
      const conv = activeConversationItem.conversation;
      const mySentInEpoch = encryptedMessages.filter(
        (m) =>
          m.sender_id === currentUser.id &&
          m.session_epoch === conv.session_epoch
      );
      const nextSequence =
        mySentInEpoch.reduce(
          (max, m) => Math.max(max, Number(m.sequence_number) || 0),
          0
        ) + 1;

      const payload: PlaintextMessagePayload = {
        text: textToSend,
        timestamp: new Date().toISOString(),
        replyToPreview: replySnapshot,
        fileAttachment: null,
      };

      const envelope = encryptMessageForPeer({
        plaintextPayload: payload,
        conversationId: conv.id,
        senderIdentity: localDevice,
        recipientX25519PublicKeyHex: activePeerPrimaryDevice.x25519_public_key,
        sequenceNumber: nextSequence,
        sessionEpoch: conv.session_epoch,
      });

      const isP2POpen = peerSessionRef.current?.isP2PReady() ?? false;
      const transportMode =
        webrtcTelemetry?.topology === "direct_p2p" && isP2POpen
          ? "webrtc_p2p"
          : webrtcTelemetry?.topology === "turn_relay" && isP2POpen
            ? "webrtc_turn"
            : "store_and_forward";

      const ttl = conv.ephemeral_ttl_seconds;
      const expiresAt = ttl
        ? new Date(Date.now() + ttl * 1000).toISOString()
        : null;

      // 1. Transmit over P2P DataChannel immediately if connected
      if (peerSessionRef.current) {
        peerSessionRef.current.sendWirePacket({
          type: "encrypted_message",
          conversationId: conv.id,
          senderId: currentUser.id,
          envelope,
          sentAt: new Date().toISOString(),
        });
        peerSessionRef.current.sendWirePacket({
          type: "typing_signal",
          conversationId: conv.id,
          senderId: currentUser.id,
          isTyping: false,
          sentAt: new Date().toISOString(),
        });
      }

      // 2. Persist encrypted envelope (ciphertext only, zero plaintext) for asynchronous sync and multi-device history
      const { data: insertedMsg } = await supabase
        .from("encrypted_messages")
        .insert({
          conversation_id: conv.id,
          sender_id: currentUser.id,
          sender_device_id: localDevice.deviceId,
          recipient_id: activeConversationItem.peer.id,
          ciphertext: envelope.ciphertext,
          nonce: envelope.nonce,
          ephemeral_public_key: envelope.ephemeralPublicKey,
          sender_ed25519_public_key: envelope.senderEd25519PublicKey,
          sender_x25519_public_key: envelope.senderX25519PublicKey,
          signature: envelope.signature,
          sequence_number: envelope.sequenceNumber,
          session_epoch: envelope.sessionEpoch,
          algorithm: envelope.algorithm,
          message_type: "text",
          reply_to_id: replySnapshot?.id ?? null,
          transport_mode: transportMode,
          ephemeral_ttl_seconds: ttl,
          expires_at: expiresAt,
        })
        .select("*")
        .single();

      if (insertedMsg) {
        const msgRecord = insertedMsg as EncryptedMessageRecord;
        setEncryptedMessages((prev) =>
          prev.some((m) => m.id === msgRecord.id) ? prev : [...prev, msgRecord]
        );
        // Notify peer over P2P DataChannel / Wire channel immediately after insert
        peerSessionRef.current?.sendWirePacket({
          type: "encrypted_message",
          conversationId: conv.id,
          senderId: currentUser.id,
          messageId: msgRecord.id,
          envelope,
          sentAt: new Date().toISOString(),
        });
      }

      await supabase
        .from("conversations")
        .update({ updated_at: new Date().toISOString() })
        .eq("id", conv.id);
    } finally {
      setSendingMessage(false);
    }
  }

  // Encrypted P2P File Transfer Handler (Chunking + XChaCha20-Poly1305 + SHA-256 Integrity)
  async function handleFileSelection(file: File) {
    if (
      !currentUser ||
      !localDevice ||
      !activeConversationItem ||
      !activePeerPrimaryDevice
    ) {
      return;
    }

    const maxBytes = (preferences.max_file_size_mb || 25) * 1024 * 1024;
    if (file.size > maxBytes) {
      alert(
        `File exceeds configured maximum limit of ${preferences.max_file_size_mb} MB.`
      );
      return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(arrayBuffer);
    const transferId =
      typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : `tf-${Date.now()}`;

    const { chunks, fullFileSha256Hex } = splitAndEncryptFile({
      fileBytes,
      transferId,
      myX25519SecretKeyHex: localDevice.x25519SecretKeyHex,
      peerX25519PublicKeyHex: activePeerPrimaryDevice.x25519_public_key,
      chunkSizeBytes: 16384,
    });

    // Register transfer state locally
    outgoingTransferControlRef.current[transferId] = {
      paused: false,
      cancelled: false,
    };

    setFileTransfers((prev) => ({
      ...prev,
      [transferId]: {
        transferId,
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type || "application/octet-stream",
        sha256Hash: fullFileSha256Hex,
        totalChunks: chunks.length,
        receivedChunks: chunks,
        direction: "outgoing",
        status: "transferring",
        reassembledBytes: fileBytes,
      },
    }));

    // For files <= 256 KB, also embed encrypted chunks in the encrypted message payload so offline recipients can reassemble and verify immediately
    const inlineEncryptedChunksJson =
      file.size <= 262144 ? JSON.stringify(chunks) : undefined;

    const conv = activeConversationItem.conversation;
    const mySentInEpoch = encryptedMessages.filter(
      (m) =>
        m.sender_id === currentUser.id && m.session_epoch === conv.session_epoch
    );
    const nextSequence =
      mySentInEpoch.reduce(
        (max, m) => Math.max(max, Number(m.sequence_number) || 0),
        0
      ) + 1;

    const manifestPayload: PlaintextMessagePayload = {
      text: `Encrypted File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`,
      timestamp: new Date().toISOString(),
      fileAttachment: {
        transferId,
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type || "application/octet-stream",
        sha256Hash: fullFileSha256Hex,
        totalChunks: chunks.length,
        encryptedDataBase64: inlineEncryptedChunksJson,
      },
    };

    const envelope = encryptMessageForPeer({
      plaintextPayload: manifestPayload,
      conversationId: conv.id,
      senderIdentity: localDevice,
      recipientX25519PublicKeyHex: activePeerPrimaryDevice.x25519_public_key,
      sequenceNumber: nextSequence,
      sessionEpoch: conv.session_epoch,
    });

    const ttl = conv.ephemeral_ttl_seconds;
    const expiresAt = ttl
      ? new Date(Date.now() + ttl * 1000).toISOString()
      : null;

    // 1. Transmit encrypted manifest over WebRTC P2P DataChannel / Wire channel immediately
    peerSessionRef.current?.sendWirePacket({
      type: "encrypted_message",
      conversationId: conv.id,
      senderId: currentUser.id,
      envelope,
      sentAt: new Date().toISOString(),
    });

    const { data: insertedMsg } = await supabase
      .from("encrypted_messages")
      .insert({
        conversation_id: conv.id,
        sender_id: currentUser.id,
        sender_device_id: localDevice.deviceId,
        recipient_id: activeConversationItem.peer.id,
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        ephemeral_public_key: envelope.ephemeralPublicKey,
        sender_ed25519_public_key: envelope.senderEd25519PublicKey,
        sender_x25519_public_key: envelope.senderX25519PublicKey,
        signature: envelope.signature,
        sequence_number: envelope.sequenceNumber,
        session_epoch: envelope.sessionEpoch,
        algorithm: envelope.algorithm,
        message_type: "file_manifest",
        transport_mode: peerSessionRef.current?.isP2PReady()
          ? "webrtc_p2p"
          : "store_and_forward",
        ephemeral_ttl_seconds: ttl,
        expires_at: expiresAt,
      })
      .select("*")
      .single();

    if (insertedMsg) {
      const msgRec = insertedMsg as EncryptedMessageRecord;
      setEncryptedMessages((prev) =>
        prev.some((m) => m.id === msgRec.id) ? prev : [...prev, msgRec]
      );
      peerSessionRef.current?.sendWirePacket({
        type: "encrypted_message",
        conversationId: conv.id,
        senderId: currentUser.id,
        messageId: msgRec.id,
        envelope,
        sentAt: new Date().toISOString(),
      });
    }

    // Stream encrypted chunks over P2P DataChannel / Wire channel with pause/cancel support
    for (let i = 0; i < chunks.length; i++) {
      const ctrl = outgoingTransferControlRef.current[transferId];
      if (ctrl?.cancelled) {
        setFileTransfers((prev) => ({
          ...prev,
          [transferId]: { ...prev[transferId], status: "cancelled" },
        }));
        return;
      }

      while (outgoingTransferControlRef.current[transferId]?.paused) {
        await new Promise((r) => setTimeout(r, 200));
        if (outgoingTransferControlRef.current[transferId]?.cancelled) return;
      }

      peerSessionRef.current?.sendWirePacket({
        type: "file_chunk",
        conversationId: conv.id,
        senderId: currentUser.id,
        fileChunk: chunks[i],
        sentAt: new Date().toISOString(),
      });

      if (chunks.length > 1) {
        await new Promise((r) => setTimeout(r, 35));
      }
    }

    setFileTransfers((prev) => ({
      ...prev,
      [transferId]: {
        ...prev[transferId],
        status: "completed",
      },
    }));

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      peer_user_id: activeConversationItem.peer.id,
      conversation_id: conv.id,
      event_type: "file_transfer_verified",
      severity: "success",
      title: `Encrypted File Transmitted (${file.name})`,
      description: `Split into ${chunks.length} XChaCha20-Poly1305 encrypted chunks with SHA-256 digest ${fullFileSha256Hex.slice(0, 16)}...`,
      metadata: {
        transfer_id: transferId,
        file_size: file.size,
        total_chunks: chunks.length,
        sha256: fullFileSha256Hex,
      },
    });
  }

  // Decrypt, Verify SHA-256 Integrity, and Download File Attachment
  function handleVerifyAndDownloadFile(
    attachment: NonNullable<PlaintextMessagePayload["fileAttachment"]>,
    senderX25519PubHex: string
  ) {
    if (!localDevice || !currentUser) return;

    try {
      const transferState = fileTransfers[attachment.transferId];
      let chunksToDecrypt: EncryptedFileChunk[] =
        transferState?.receivedChunks ?? [];

      if (
        chunksToDecrypt.length < attachment.totalChunks &&
        attachment.encryptedDataBase64
      ) {
        chunksToDecrypt = JSON.parse(
          attachment.encryptedDataBase64
        ) as EncryptedFileChunk[];
      }

      const verifiedBytes = decryptAndReassembleFile({
        chunks: chunksToDecrypt,
        expectedFullSha256Hex: attachment.sha256Hash,
        myX25519SecretKeyHex: localDevice.x25519SecretKeyHex,
        peerX25519PublicKeyHex: senderX25519PubHex,
      });

      const blob = new Blob([verifiedBytes.buffer as ArrayBuffer], {
        type: attachment.mimeType || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = attachment.fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(
        `Cryptographic File Integrity Error: ${
          err instanceof Error ? err.message : "Failed to verify chunks"
        }`
      );
    }
  }

  // Configure Disappearing Message TTL on Active Conversation
  async function handleSetEphemeralTtl(ttlSeconds: number | null) {
    if (!activeConversationItem || !currentUser) return;
    const convId = activeConversationItem.conversation.id;

    await supabase
      .from("conversations")
      .update({
        ephemeral_ttl_seconds: ttlSeconds,
        updated_at: new Date().toISOString(),
      })
      .eq("id", convId);

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      conversation_id: convId,
      event_type: "ephemeral_policy_changed",
      severity: "info",
      title: ttlSeconds
        ? `Disappearing Messages Set to ${ttlSeconds}s`
        : "Disappearing Messages Disabled",
      description: ttlSeconds
        ? `New messages in this conversation will automatically expire ${ttlSeconds} seconds after creation.`
        : "Messages in this conversation will remain stored in encrypted form.",
      metadata: { ephemeral_ttl_seconds: ttlSeconds },
    });

    peerSessionRef.current?.sendWirePacket({
      type: "session_control",
      conversationId: convId,
      senderId: currentUser.id,
      sessionControl: {
        action: "ephemeral_ttl_changed",
        ephemeralTtlSeconds: ttlSeconds,
      },
      sentAt: new Date().toISOString(),
    });

    await refreshWorkspaceData(currentUser.id);
  }

  // Rotate Session Epoch Keys
  async function handleRotateSessionKeys() {
    if (!activeConversationItem || !currentUser) return;
    const conv = activeConversationItem.conversation;
    const nextEpoch = conv.session_epoch + 1;

    await supabase
      .from("conversations")
      .update({
        session_epoch: nextEpoch,
        last_key_rotation_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", conv.id);

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      peer_user_id: activeConversationItem.peer.id,
      conversation_id: conv.id,
      event_type: "key_rotated",
      severity: "info",
      title: `Conversation Session Epoch Rotated (Epoch ${nextEpoch})`,
      description: `Derived fresh HKDF-SHA256 session context with @${activeConversationItem.peer.username}.`,
      metadata: { session_epoch: nextEpoch },
    });

    peerSessionRef.current?.sendWirePacket({
      type: "session_control",
      conversationId: conv.id,
      senderId: currentUser.id,
      sessionControl: {
        action: "key_rotated",
        sessionEpoch: nextEpoch,
      },
      sentAt: new Date().toISOString(),
    });

    await refreshWorkspaceData(currentUser.id);
  }

  // Verify Peer Identity (Manual or QR Scan)
  async function handleVerifyPeer(
    peerId: string,
    peerDeviceId: string | null,
    fingerprint: string,
    safetyNumber: string,
    method: "manual" | "qr_scan"
  ) {
    if (!currentUser) return;

    await supabase.from("contact_verifications").upsert(
      {
        verifier_user_id: currentUser.id,
        contact_user_id: peerId,
        contact_device_id: peerDeviceId,
        verified_fingerprint: fingerprint,
        safety_number: safetyNumber,
        verification_method: method,
        is_verified: true,
        verified_at: new Date().toISOString(),
      },
      { onConflict: "verifier_user_id,contact_user_id,verified_fingerprint" }
    );

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      peer_user_id: peerId,
      device_id: peerDeviceId,
      event_type: "identity_verified",
      severity: "success",
      title: `Contact Identity Verified (${method === "qr_scan" ? "QR Scan" : "Safety Number"})`,
      description: `Confirmed public identity fingerprint ${fingerprint} and 60-digit safety number.`,
      metadata: {
        verified_fingerprint: fingerprint,
        method,
      },
    });

    await refreshWorkspaceData(currentUser.id);
  }

  // Revoke Device
  async function handleRevokeDevice(deviceId: string, fingerprint: string) {
    if (!currentUser) return;

    await supabase
      .from("devices")
      .update({ is_revoked: true })
      .eq("id", deviceId)
      .eq("user_id", currentUser.id);

    await supabase.from("device_revocations").insert({
      user_id: currentUser.id,
      device_id: deviceId,
      revoked_fingerprint: fingerprint,
      reason: "Revoked via CipherMesh Security Center",
    });

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      device_id: deviceId,
      event_type: "device_revoked",
      severity: "warning",
      title: "Trusted Device Revoked",
      description: `Revoked device with fingerprint ${fingerprint}. Peers will no longer trust keys from this device.`,
      metadata: { fingerprint },
    });

    await refreshWorkspaceData(currentUser.id);
  }

  // Delete Message
  async function handleDeleteMessage(messageId: string) {
    await supabase
      .from("encrypted_messages")
      .update({
        is_deleted: true,
        ciphertext: "00",
      })
      .eq("id", messageId);

    setEncryptedMessages((prev) => prev.filter((m) => m.id !== messageId));
  }

  // Terminate Session
  async function handleTerminateSession() {
    if (!currentUser || !activeConversationItem) return;
    const conv = activeConversationItem.conversation;

    peerSessionRef.current?.destroy();
    peerSessionRef.current = null;

    await supabase
      .from("conversations")
      .update({
        session_epoch: conv.session_epoch + 1,
        last_key_rotation_at: new Date().toISOString(),
      })
      .eq("id", conv.id);

    await supabase.from("security_events").insert({
      user_id: currentUser.id,
      conversation_id: conv.id,
      event_type: "session_terminated",
      severity: "warning",
      title: "Active Session Terminated & Keys Ratcheted",
      description:
        "Closed active WebRTC P2P DataChannel and incremented session epoch.",
      metadata: { conversation_id: conv.id },
    });

    setActiveConversationId(null);
    await refreshWorkspaceData(currentUser.id);
  }

  async function handleSignOut() {
    if (peerSessionRef.current) {
      peerSessionRef.current.destroy();
    }
    await supabase.auth.signOut();
    router.replace("/login");
  }

  if (loadingInitial || !currentUser) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-[#090a0f] text-white">
        <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-[#11131a] px-6 py-4">
          <Loader2 className="h-5 w-5 animate-spin text-violet-400" />
          <div className="text-left">
            <div className="text-sm font-medium">
              Initializing CipherMesh Cryptographic Node...
            </div>
            <div className="font-mono text-xs text-zinc-400">
              Loading Ed25519 + X25519 Keystore & Verifying Signatures
            </div>
          </div>
        </div>
      </div>
    );
  }

  const filteredConversations = conversations.filter((item) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.peer.username.toLowerCase().includes(q) ||
      item.peer.display_name.toLowerCase().includes(q)
    );
  });

  const directoryPeers = allProfiles.filter(
    (p) =>
      p.id !== currentUser.id &&
      (!newConvSearch.trim() ||
        p.username.toLowerCase().includes(newConvSearch.toLowerCase()) ||
        p.display_name.toLowerCase().includes(newConvSearch.toLowerCase()))
  );

  const isActivePeerVerified = Boolean(
    activePeer &&
      activePeerPrimaryDevice &&
      verifications.some(
        (v) =>
          v.contact_user_id === activePeer.id &&
          v.verified_fingerprint === activePeerPrimaryDevice.fingerprint &&
          v.is_verified
      )
  );

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#090a0f] text-[#f3f4f6]">
      {/* LEFT SIDEBAR: Navigation, Operator Profile, Search, Conversation List */}
      <aside
        aria-label="Workspace Navigation and Conversations"
        className={`flex h-full w-full shrink-0 flex-col border-r border-white/[0.075] bg-[#11131a] md:w-80 ${
          mobileShowChat && activeTab === "messages" ? "hidden md:flex" : "flex"
        }`}
      >
        {/* Brand & Operator Header */}
        <div className="flex h-14 items-center justify-between border-b border-white/[0.075] px-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-400">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-tight text-white">
                CipherMesh
              </div>
              <div className="font-mono text-[10px] text-emerald-400">
                @{currentUser.username}
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              void refreshWorkspaceData(currentUser.id);
              setShowNewConversationModal(true);
            }}
            aria-label="Start new encrypted conversation"
            className="inline-flex items-center gap-1 rounded-lg bg-violet-600 px-2.5 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>New</span>
          </button>
        </div>

        {/* Primary Mode Switcher (Messages / Security Center / Settings) */}
        <div className="grid grid-cols-3 gap-1 border-b border-white/[0.075] bg-[#090a0f] p-2">
          <button
            type="button"
            onClick={() => setActiveTab("messages")}
            className={`flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition-colors ${
              activeTab === "messages"
                ? "bg-violet-600 text-white"
                : "text-zinc-400 hover:bg-white/[0.04] hover:text-white"
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5" />
            <span>Chats</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("security")}
            className={`flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition-colors ${
              activeTab === "security"
                ? "bg-violet-600 text-white"
                : "text-zinc-400 hover:bg-white/[0.04] hover:text-white"
            }`}
          >
            <Shield className="h-3.5 w-3.5" />
            <span>Security</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("settings")}
            className={`flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-medium transition-colors ${
              activeTab === "settings"
                ? "bg-violet-600 text-white"
                : "text-zinc-400 hover:bg-white/[0.04] hover:text-white"
            }`}
          >
            <Settings className="h-3.5 w-3.5" />
            <span>Settings</span>
          </button>
        </div>

        {/* Search Conversations */}
        <div className="border-b border-white/[0.075] p-3">
          <div className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-3.5 w-3.5 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search encrypted channels..."
              aria-label="Search conversations"
              className="w-full rounded-lg border border-white/10 bg-[#090a0f] py-1.5 pr-3 pl-8 text-xs text-white placeholder-zinc-500 focus:border-violet-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Conversation List */}
        <div className="flex-1 space-y-1 overflow-y-auto p-2">
          {filteredConversations.length === 0 ? (
            <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
              <Lock className="h-6 w-6 text-zinc-600" />
              <p className="mt-2 text-xs font-medium text-zinc-300">
                No Active Encrypted Channels
              </p>
              <p className="mt-1 text-[11px] text-zinc-500">
                Start a conversation with another registered node to exchange
                X25519 keys.
              </p>
              <button
                type="button"
                onClick={() => setShowNewConversationModal(true)}
                className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/10 px-3 py-1.5 text-xs font-medium text-violet-300 hover:bg-violet-500/20"
              >
                <UserPlus className="h-3.5 w-3.5" />
                <span>Select Peer Node</span>
              </button>
            </div>
          ) : (
            filteredConversations.map((item) => {
              const isSelected =
                item.conversation.id === activeConversationId &&
                activeTab === "messages";
              const isOnline = onlineUserIds.has(item.peer.id);
              const peerDevs = allDevicesByUser[item.peer.id] ?? [];
              const peerPrimary = peerDevs.find((d) => !d.is_revoked);
              const isPeerVerif = Boolean(
                peerPrimary &&
                  verifications.some(
                    (v) =>
                      v.contact_user_id === item.peer.id &&
                      v.verified_fingerprint === peerPrimary.fingerprint &&
                      v.is_verified
                  )
              );

              return (
                <button
                  key={item.conversation.id}
                  type="button"
                  onClick={() => {
                    setActiveConversationId(item.conversation.id);
                    setActiveTab("messages");
                    setMobileShowChat(true);
                  }}
                  className={`flex w-full items-center gap-3 rounded-xl p-2.5 text-left transition-colors ${
                    isSelected
                      ? "border border-violet-500/40 bg-violet-500/12"
                      : "border border-transparent hover:bg-white/[0.04]"
                  }`}
                >
                  <div className="relative shrink-0">
                    <div
                      className="flex h-10 w-10 items-center justify-center rounded-xl font-mono text-xs font-semibold text-white"
                      style={{
                        backgroundColor: item.peer.avatar_color || "#7C3AED",
                      }}
                    >
                      {item.peer.display_name.slice(0, 2).toUpperCase()}
                    </div>
                    <span
                      className={`absolute -right-0.5 -bottom-0.5 h-2.5 w-2.5 rounded-full border-2 border-[#11131a] ${
                        isOnline ? "bg-emerald-400" : "bg-zinc-600"
                      }`}
                    />
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-1">
                      <div className="flex items-center gap-1.5 truncate">
                        <span className="truncate text-xs font-semibold text-white">
                          {item.peer.display_name}
                        </span>
                        {isPeerVerif ? (
                          <ShieldCheck
                            aria-label="Verified identity"
                            className="h-3.5 w-3.5 shrink-0 text-emerald-400"
                          />
                        ) : (
                          <ShieldAlert
                            aria-label="Unverified identity"
                            className="h-3.5 w-3.5 shrink-0 text-amber-400/80"
                          />
                        )}
                      </div>
                      <span className="shrink-0 font-mono text-[10px] text-zinc-500">
                        {new Date(item.lastMessageAt).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </span>
                    </div>

                    <div className="mt-0.5 flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[11px] text-zinc-400">
                        @{item.peer.username}
                      </span>
                      {item.unreadCount > 0 && (
                        <span className="rounded-full bg-violet-600 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-white">
                          {item.unreadCount}
                        </span>
                      )}
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Bottom Local Keystore Status & Logout */}
        <div className="border-t border-white/[0.075] bg-[#090a0f] p-3">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-400">
                <Lock className="h-3 w-3" />
                <span>KEYSTORE UNLOCKED</span>
              </div>
              <div className="mt-0.5 truncate font-mono text-[10px] text-zinc-500">
                FP: {localDevice?.fingerprint.slice(0, 19)}...
              </div>
            </div>

            <button
              type="button"
              onClick={() => void handleSignOut()}
              aria-label="Sign out"
              className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-[#11131a] px-2.5 py-1.5 text-xs text-zinc-300 hover:border-red-500/40 hover:text-red-300"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Exit</span>
            </button>
          </div>
        </div>
      </aside>

      {/* CENTRAL PANEL: Active View (Messages / Security Center / Settings) */}
      <main className="flex flex-1 overflow-hidden">
        {activeTab === "security" ? (
          <SecurityCenterView
            currentUser={currentUser}
            localDevice={localDevice}
            myDevices={myDevices}
            peerProfile={activePeer}
            peerActiveDevice={activePeerPrimaryDevice}
            activeConversationId={activeConversationId}
            sessionEpoch={
              activeConversationItem?.conversation.session_epoch ?? 1
            }
            lastKeyRotationAt={
              activeConversationItem?.conversation.last_key_rotation_at ?? null
            }
            telemetry={webrtcTelemetry}
            verifications={verifications}
            securityEvents={securityEvents}
            identityChangedPeers={identityChangedPeers}
            onVerifyPeer={handleVerifyPeer}
            onRevokeDevice={handleRevokeDevice}
            onRotateSessionKeys={handleRotateSessionKeys}
            onRotateDeviceIdentityKeys={async () => {
              const rotated = await rotateAndPublishDeviceKeys(
                supabase,
                currentUser.id
              );
              setLocalDevice(rotated);
              await refreshWorkspaceData(currentUser.id);
            }}
            onTerminateSession={handleTerminateSession}
          />
        ) : activeTab === "settings" ? (
          <SettingsView
            currentUser={currentUser}
            localDevice={localDevice}
            preferences={preferences}
            onUpdateProfile={async (updates) => {
              await supabase
                .from("profiles")
                .update({
                  ...updates,
                  updated_at: new Date().toISOString(),
                })
                .eq("id", currentUser.id);
              await refreshWorkspaceData(currentUser.id);
            }}
            onUpdatePreferences={async (updates) => {
              await supabase.from("user_preferences").upsert({
                ...preferences,
                ...updates,
                user_id: currentUser.id,
                updated_at: new Date().toISOString(),
              });
              await refreshWorkspaceData(currentUser.id);
            }}
          />
        ) : !activeConversationItem || !activePeer ? (
          /* Empty Conversation State */
          <div className="flex flex-1 flex-col items-center justify-center bg-[#090a0f] p-6 text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-violet-500/30 bg-violet-500/10 text-violet-400">
              <Shield className="h-7 w-7" />
            </div>
            <h2 className="mt-4 text-lg font-semibold text-white">
              CipherMesh Encrypted Workspace
            </h2>
            <p className="mt-1.5 max-w-md text-xs leading-relaxed text-zinc-400">
              Select a conversation from the sidebar or initiate a new peer
              connection. All messages are encrypted locally using
              X25519-HKDF-SHA256-XChaCha20-Poly1305 and signed with Ed25519.
            </p>
            <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => setShowNewConversationModal(true)}
                className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-xs font-medium text-white hover:bg-violet-500"
              >
                <Plus className="h-4 w-4" />
                <span>Start Encrypted Conversation</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("security")}
                className="inline-flex items-center gap-2 rounded-lg border border-white/12 bg-[#11131a] px-4 py-2.5 text-xs font-medium text-zinc-200 hover:border-white/25"
              >
                <Shield className="h-4 w-4 text-violet-400" />
                <span>Inspect Security Center</span>
              </button>
            </div>
          </div>
        ) : (
          /* ACTIVE ENCRYPTED CONVERSATION INTERFACE */
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDraggingFile(true);
            }}
            onDragLeave={() => setIsDraggingFile(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDraggingFile(false);
              const droppedFile = e.dataTransfer.files?.[0];
              if (droppedFile) {
                void handleFileSelection(droppedFile);
              }
            }}
            className="relative flex flex-1 flex-col bg-[#090a0f]"
          >
            {/* Drag-and-Drop Overlay */}
            {isDraggingFile && (
              <div className="pointer-events-none absolute inset-0 z-40 flex flex-col items-center justify-center bg-[#090a0f]/90 backdrop-blur-sm">
                <div className="rounded-2xl border-2 border-dashed border-violet-500 bg-[#11131a] p-8 text-center">
                  <Lock className="mx-auto h-8 w-8 text-violet-400" />
                  <div className="mt-2 text-sm font-semibold text-white">
                    Drop File to Encrypt & Transmit P2P
                  </div>
                  <div className="mt-1 font-mono text-xs text-zinc-400">
                    Each 16 KB chunk is encrypted with XChaCha20-Poly1305 +
                    SHA-256 integrity
                  </div>
                </div>
              </div>
            )}

            {/* Top Conversation Header */}
            <header className="flex h-14 shrink-0 items-center justify-between border-b border-white/[0.075] bg-[#11131a] px-4">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setMobileShowChat(false)}
                  aria-label="Back to conversation list"
                  className="rounded-lg p-1.5 text-zinc-400 hover:bg-white/[0.06] md:hidden"
                >
                  <ArrowLeft className="h-4 w-4" />
                </button>

                <div
                  className="flex h-9 w-9 items-center justify-center rounded-xl font-mono text-xs font-semibold text-white"
                  style={{
                    backgroundColor: activePeer.avatar_color || "#7C3AED",
                  }}
                >
                  {activePeer.display_name.slice(0, 2).toUpperCase()}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white">
                      {activePeer.display_name}
                    </span>
                    <span className="font-mono text-xs text-zinc-400">
                      @{activePeer.username}
                    </span>
                  </div>

                  {/* Clickable Subtle Encryption & Transport Indicator */}
                  <button
                    type="button"
                    onClick={() => setActiveTab("security")}
                    className="mt-0.5 flex items-center gap-2 font-mono text-[10px] text-zinc-400 hover:text-white"
                  >
                    {isActivePeerVerified ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400">
                        <ShieldCheck className="h-3 w-3" />
                        <span>VERIFIED E2EE</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-amber-400">
                        <ShieldAlert className="h-3 w-3" />
                        <span>ENCRYPTED (UNVERIFIED PEER)</span>
                      </span>
                    )}
                    <span>•</span>
                    <span className="text-sky-400">
                      {webrtcTelemetry?.topology === "direct_p2p"
                        ? "DIRECT P2P"
                        : webrtcTelemetry?.topology === "turn_relay"
                          ? "TURN RELAY"
                          : "STORE & FORWARD"}
                    </span>
                    {localDevice && activePeerPrimaryDevice && (
                      <>
                        <span className="hidden sm:inline">•</span>
                        <span className="hidden text-zinc-500 sm:inline">
                          {deriveSessionIdentifier(
                            activeConversationItem.conversation.id,
                            localDevice.x25519PublicKeyHex,
                            activePeerPrimaryDevice.x25519_public_key,
                            activeConversationItem.conversation.session_epoch
                          )}
                        </span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Right Controls: Disappearing Messages Selector, Reconnect, Contextual Inspector Toggle */}
              <div className="flex items-center gap-2">
                {/* Ephemeral TTL Selector */}
                <div className="hidden items-center gap-1 rounded-lg border border-white/10 bg-[#090a0f] px-2 py-1 sm:flex">
                  <Clock className="h-3.5 w-3.5 text-violet-400" />
                  <span className="font-mono text-[10px] text-zinc-400">
                    TTL:
                  </span>
                  {EPHEMERAL_OPTIONS.map((opt) => {
                    const currentTtl =
                      activeConversationItem.conversation.ephemeral_ttl_seconds;
                    const active = currentTtl === opt.value;
                    return (
                      <button
                        key={opt.label}
                        type="button"
                        onClick={() => void handleSetEphemeralTtl(opt.value)}
                        className={`rounded px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                          active
                            ? "bg-violet-600 text-white"
                            : "text-zinc-400 hover:text-white"
                        }`}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>

                {/* Reconnect P2P Button */}
                <button
                  type="button"
                  onClick={() => peerSessionRef.current?.reconnect()}
                  title="Renegotiate WebRTC P2P ICE Candidates"
                  className="rounded-lg border border-white/10 bg-[#090a0f] p-2 text-zinc-400 hover:border-white/25 hover:text-white"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                </button>

                {/* Contextual Right Panel Toggle */}
                <button
                  type="button"
                  onClick={() => setShowRightInspector((prev) => !prev)}
                  aria-label="Toggle contact security sidebar"
                  className="rounded-lg border border-white/10 bg-[#090a0f] p-2 text-zinc-400 hover:border-white/25 hover:text-white"
                >
                  {showRightInspector ? (
                    <PanelRightClose className="h-4 w-4" />
                  ) : (
                    <PanelRightOpen className="h-4 w-4" />
                  )}
                </button>
              </div>
            </header>

            {/* Ephemeral Transparency Notice Strip (if enabled) */}
            {activeConversationItem.conversation.ephemeral_ttl_seconds && (
              <div className="flex items-center justify-between border-b border-violet-500/20 bg-violet-500/10 px-4 py-1.5 text-[11px] text-violet-200">
                <div className="flex items-center gap-2">
                  <Clock className="h-3.5 w-3.5 text-violet-400" />
                  <span>
                    Disappearing messages enabled (
                    {activeConversationItem.conversation.ephemeral_ttl_seconds}s
                    expiry). Note: Ephemeral timers remove messages from
                    CipherMesh devices and storage, but cannot prevent external
                    cameras or OS screenshots by a recipient.
                  </span>
                </div>
              </div>
            )}

            {/* Message History Stream */}
            <div className="flex-1 space-y-3 overflow-y-auto p-4">
              {/* Session Cryptographic Header Banner */}
              <div className="mx-auto max-w-xl rounded-xl border border-white/[0.06] bg-[#11131a] p-3.5 text-center">
                <div className="flex items-center justify-center gap-1.5 font-mono text-[11px] text-violet-400">
                  <Lock className="h-3.5 w-3.5" />
                  <span>END-TO-END ENCRYPTED CHANNEL</span>
                </div>
                <p className="mt-1 text-xs text-zinc-400">
                  Messages and files in this channel are encrypted on your
                  device with{" "}
                  <span className="font-mono text-zinc-300">
                    XChaCha20-Poly1305
                  </span>{" "}
                  and signed with{" "}
                  <span className="font-mono text-zinc-300">Ed25519</span>. The
                  server never sees plaintext content.
                </p>
              </div>

              {decryptedMessages.map((item) => {
                const isMe = item.record.sender_id === currentUser.id;
                const attachment = item.plaintext?.fileAttachment;
                const transfer = attachment
                  ? fileTransfers[attachment.transferId]
                  : null;

                return (
                  <div
                    key={item.record.id}
                    className={`flex flex-col ${
                      isMe ? "items-end" : "items-start"
                    }`}
                  >
                    <div
                      className={`group relative max-w-[85%] rounded-2xl border px-4 py-2.5 sm:max-w-[70%] ${
                        isMe
                          ? "border-violet-500/35 bg-violet-600/15 text-white"
                          : "border-white/10 bg-[#11131a] text-zinc-100"
                      }`}
                    >
                      {/* Reply Preview */}
                      {item.plaintext?.replyToPreview && (
                        <div className="mb-2 rounded-lg border-l-2 border-violet-400 bg-black/30 px-2.5 py-1.5 text-[11px] text-zinc-300">
                          <div className="font-semibold text-violet-300">
                            {item.plaintext.replyToPreview.senderName}
                          </div>
                          <div className="truncate text-zinc-400">
                            {item.plaintext.replyToPreview.snippet}
                          </div>
                        </div>
                      )}

                      {/* Decryption Error or Plaintext Content */}
                      {item.decryptionError ? (
                        <div className="flex items-center gap-2 text-xs text-amber-300">
                          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                          <span>{item.decryptionError}</span>
                        </div>
                      ) : (
                        <div className="text-sm leading-relaxed break-words whitespace-pre-wrap">
                          {item.plaintext?.text}
                        </div>
                      )}

                      {/* Encrypted File Attachment Card */}
                      {attachment && (
                        <div className="mt-2.5 rounded-xl border border-white/10 bg-[#090a0f] p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div className="flex items-center gap-2.5 min-w-0">
                              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-400">
                                <FileText className="h-4 w-4" />
                              </div>
                              <div className="min-w-0">
                                <div className="truncate text-xs font-medium text-white">
                                  {attachment.fileName}
                                </div>
                                <div className="font-mono text-[10px] text-zinc-400">
                                  {(attachment.fileSize / 1024).toFixed(1)} KB •{" "}
                                  {attachment.totalChunks} chunks • SHA-256:{" "}
                                  {attachment.sha256Hash.slice(0, 10)}...
                                </div>
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={() =>
                                handleVerifyAndDownloadFile(
                                  attachment,
                                  item.record.sender_x25519_public_key
                                )
                              }
                              className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-violet-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-violet-500"
                            >
                              <Download className="h-3.5 w-3.5" />
                              <span>Verify & Save</span>
                            </button>
                          </div>

                          {/* Progress / Pause / Resume / Cancel Bar if Active */}
                          {transfer && (
                            <div className="mt-2.5 border-t border-white/[0.06] pt-2">
                              <div className="flex items-center justify-between font-mono text-[10px] text-zinc-400">
                                <span>
                                  STATUS: {transfer.status.toUpperCase()} (
                                  {transfer.receivedChunks.length}/
                                  {transfer.totalChunks} CHUNKS)
                                </span>
                                {transfer.status === "transferring" &&
                                  transfer.direction === "outgoing" && (
                                    <div className="flex items-center gap-1.5">
                                      <button
                                        type="button"
                                        onClick={() => {
                                          if (
                                            outgoingTransferControlRef.current[
                                              attachment.transferId
                                            ]
                                          ) {
                                            outgoingTransferControlRef.current[
                                              attachment.transferId
                                            ].paused = true;
                                          }
                                          setFileTransfers((prev) => ({
                                            ...prev,
                                            [attachment.transferId]: {
                                              ...prev[attachment.transferId],
                                              status: "paused",
                                            },
                                          }));
                                        }}
                                        className="rounded bg-white/10 p-1 hover:bg-white/20"
                                      >
                                        <Pause className="h-3 w-3" />
                                      </button>
                                      <button
                                        type="button"
                                        onClick={() => {
                                          if (
                                            outgoingTransferControlRef.current[
                                              attachment.transferId
                                            ]
                                          ) {
                                            outgoingTransferControlRef.current[
                                              attachment.transferId
                                            ].cancelled = true;
                                          }
                                          setFileTransfers((prev) => ({
                                            ...prev,
                                            [attachment.transferId]: {
                                              ...prev[attachment.transferId],
                                              status: "cancelled",
                                            },
                                          }));
                                        }}
                                        className="rounded bg-red-500/20 p-1 text-red-300 hover:bg-red-500/30"
                                      >
                                        <X className="h-3 w-3" />
                                      </button>
                                    </div>
                                  )}
                                {transfer.status === "paused" &&
                                  transfer.direction === "outgoing" && (
                                    <button
                                      type="button"
                                      onClick={() => {
                                        if (
                                          outgoingTransferControlRef.current[
                                            attachment.transferId
                                          ]
                                        ) {
                                          outgoingTransferControlRef.current[
                                            attachment.transferId
                                          ].paused = false;
                                        }
                                        setFileTransfers((prev) => ({
                                          ...prev,
                                          [attachment.transferId]: {
                                            ...prev[attachment.transferId],
                                            status: "transferring",
                                          },
                                        }));
                                      }}
                                      className="inline-flex items-center gap-1 rounded bg-emerald-500/20 px-1.5 py-0.5 text-emerald-300"
                                    >
                                      <Play className="h-3 w-3" />
                                      <span>Resume</span>
                                    </button>
                                  )}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Message Footer: Timestamp, Seq, Ephemeral Countdown, Receipt & Actions */}
                      <div className="mt-1.5 flex items-center justify-between gap-3 font-mono text-[10px] text-zinc-400">
                        <div className="flex items-center gap-2">
                          <span>
                            {new Date(
                              item.record.created_at
                            ).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}
                          </span>
                          <span>•</span>
                          <span>SEQ #{item.record.sequence_number}</span>
                          {item.record.expires_at && (
                            <span className="inline-flex items-center gap-0.5 text-amber-400">
                              <Clock className="h-2.5 w-2.5" />
                              <span>
                                {Math.max(
                                  0,
                                  Math.ceil(
                                    (new Date(
                                      item.record.expires_at
                                    ).getTime() -
                                      nowTick) /
                                      1000
                                  )
                                )}
                                s
                              </span>
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1.5">
                          {/* Action buttons: Reply, Inspect Ciphertext Envelope, Delete */}
                          <button
                            type="button"
                            onClick={() =>
                              setReplyingTo({
                                id: item.record.id,
                                senderName: isMe
                                  ? currentUser.display_name
                                  : activePeer.display_name,
                                snippet:
                                  item.plaintext?.text.slice(0, 60) ??
                                  "Encrypted message",
                              })
                            }
                            aria-label="Reply to message"
                            className="opacity-70 hover:text-white hover:opacity-100"
                          >
                            <Reply className="h-3 w-3" />
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              setInspectingEnvelopeMsg(item.record)
                            }
                            aria-label="Inspect cryptographic envelope"
                            title="Inspect Raw Ciphertext & Ed25519 Signature"
                            className="opacity-70 hover:text-violet-300 hover:opacity-100"
                          >
                            <Eye className="h-3 w-3" />
                          </button>
                          {isMe && (
                            <button
                              type="button"
                              onClick={() =>
                                void handleDeleteMessage(item.record.id)
                              }
                              aria-label="Delete message"
                              className="opacity-70 hover:text-red-400 hover:opacity-100"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          )}

                          {isMe && (
                            <span
                              title={`Delivery status: ${item.receiptStatus}`}
                              className="ml-1"
                            >
                              {item.receiptStatus === "read" ? (
                                <CheckCheck className="h-3.5 w-3.5 text-emerald-400" />
                              ) : item.receiptStatus === "delivered" ? (
                                <CheckCheck className="h-3.5 w-3.5 text-zinc-400" />
                              ) : (
                                <Check className="h-3.5 w-3.5 text-zinc-400" />
                              )}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}

              {/* Typing Indicator */}
              {peerIsTyping && (
                <div className="flex items-center gap-2 px-2 font-mono text-xs text-violet-400">
                  <span className="inline-block h-2 w-2 animate-ping rounded-full bg-violet-400" />
                  <span>@{activePeer.username} is composing...</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Reply Banner */}
            {replyingTo && (
              <div className="flex items-center justify-between border-t border-white/[0.075] bg-[#11131a] px-4 py-2 text-xs">
                <div className="flex items-center gap-2 truncate">
                  <Reply className="h-3.5 w-3.5 text-violet-400" />
                  <span className="font-medium text-violet-300">
                    Replying to {replyingTo.senderName}:
                  </span>
                  <span className="truncate text-zinc-400">
                    {replyingTo.snippet}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setReplyingTo(null)}
                  className="text-zinc-500 hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}

            {/* Message Composer */}
            <form
              onSubmit={handleSendMessage}
              className="border-t border-white/[0.075] bg-[#11131a] p-3"
            >
              <div className="flex items-center gap-2">
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) void handleFileSelection(f);
                    e.target.value = "";
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  aria-label="Attach file for encrypted transfer"
                  title="Encrypt and send file"
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-[#090a0f] text-zinc-400 transition-colors hover:border-violet-500/40 hover:text-white"
                >
                  <Paperclip className="h-4 w-4" />
                </button>

                <input
                  type="text"
                  value={composerText}
                  onChange={(e) => {
                    setComposerText(e.target.value);
                    if (
                      preferences.show_typing_indicators &&
                      peerSessionRef.current &&
                      activeConversationId
                    ) {
                      peerSessionRef.current.sendWirePacket({
                        type: "typing_signal",
                        conversationId: activeConversationId,
                        senderId: currentUser.id,
                        isTyping: e.target.value.length > 0,
                        sentAt: new Date().toISOString(),
                      });
                    }
                  }}
                  placeholder={`Encrypt message to @${activePeer.username}...`}
                  aria-label="Encrypted message input"
                  className="h-10 flex-1 rounded-xl border border-white/10 bg-[#090a0f] px-4 text-sm text-white placeholder-zinc-500 focus:border-violet-500 focus:outline-none"
                />

                <button
                  type="submit"
                  disabled={!composerText.trim() || sendingMessage}
                  aria-label="Encrypt and send message"
                  className="inline-flex h-10 items-center gap-1.5 rounded-xl bg-violet-600 px-4 text-xs font-medium text-white transition-colors hover:bg-violet-500 disabled:opacity-50"
                >
                  <Send className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Encrypt & Send</span>
                </button>
              </div>
            </form>
          </div>
        )}

        {/* RIGHT-SIDE CONTEXTUAL INSPECTOR PANEL */}
        {activeTab === "messages" &&
          activeConversationItem &&
          activePeer &&
          showRightInspector && (
            <div className="hidden lg:block">
              <ContactSecuritySidebar
                currentUser={currentUser}
                localDevice={localDevice}
                peerProfile={activePeer}
                peerDevices={activePeerDevices}
                activeConversationId={activeConversationItem.conversation.id}
                sessionEpoch={
                  activeConversationItem.conversation.session_epoch
                }
                ephemeralTtlSeconds={
                  activeConversationItem.conversation.ephemeral_ttl_seconds
                }
                telemetry={webrtcTelemetry}
                verifications={verifications}
                isPeerOnline={onlineUserIds.has(activePeer.id)}
                identityChangedFrom={
                  identityChangedPeers[activePeer.id] ?? null
                }
                onClose={() => setShowRightInspector(false)}
                onVerifyPeer={handleVerifyPeer}
                onRotateSessionKeys={handleRotateSessionKeys}
                onOpenFullSecurityCenter={() => setActiveTab("security")}
              />
            </div>
          )}
      </main>

      {/* MODAL 1: Start New Encrypted Conversation */}
      {showNewConversationModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Start New Encrypted Conversation"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-2xl border border-white/12 bg-[#11131a] p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <UserPlus className="h-4 w-4 text-violet-400" />
                <h3 className="text-sm font-semibold text-white">
                  Establish New Encrypted Session
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowNewConversationModal(false)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4">
              <input
                type="text"
                value={newConvSearch}
                onChange={(e) => setNewConvSearch(e.target.value)}
                placeholder="Search peer username or display name..."
                className="w-full rounded-lg border border-white/10 bg-[#090a0f] px-3.5 py-2 text-xs text-white placeholder-zinc-500 focus:border-violet-500 focus:outline-none"
              />
            </div>

            <div className="mt-4 max-h-72 space-y-2 overflow-y-auto">
              {directoryPeers.length === 0 ? (
                <div className="py-8 text-center text-xs text-zinc-500">
                  No other registered nodes found matching your search.
                </div>
              ) : (
                directoryPeers.map((peer) => {
                  const peerDevs = allDevicesByUser[peer.id] ?? [];
                  const primaryDev = peerDevs.find((d) => !d.is_revoked);
                  return (
                    <button
                      key={peer.id}
                      type="button"
                      onClick={() =>
                        void handleStartOrSelectConversation(peer)
                      }
                      className="flex w-full items-center justify-between rounded-xl border border-white/[0.06] bg-[#090a0f] p-3 text-left transition-colors hover:border-violet-500/40"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div
                          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl font-mono text-xs font-semibold text-white"
                          style={{
                            backgroundColor: peer.avatar_color || "#7C3AED",
                          }}
                        >
                          {peer.display_name.slice(0, 2).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <div className="truncate text-xs font-semibold text-white">
                            {peer.display_name}
                          </div>
                          <div className="font-mono text-[11px] text-zinc-400">
                            @{peer.username}
                          </div>
                          {primaryDev && (
                            <div className="mt-0.5 truncate font-mono text-[10px] text-emerald-400">
                              FP: {primaryDev.fingerprint.slice(0, 19)}...
                            </div>
                          )}
                        </div>
                      </div>
                      <span className="rounded-lg bg-violet-600/20 px-2.5 py-1 font-mono text-[10px] text-violet-300">
                        Connect →
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: Raw Cryptographic Envelope Inspector */}
      {inspectingEnvelopeMsg && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Cryptographic Envelope Inspector"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-xl rounded-2xl border border-white/12 bg-[#11131a] p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.075] pb-3.5">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-violet-400" />
                <h3 className="text-sm font-semibold text-white">
                  Raw Cryptographic Wire Envelope Inspector
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setInspectingEnvelopeMsg(null)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3 font-mono text-xs">
              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  ALGORITHM & TRANSPORT
                </div>
                <div className="mt-1 text-violet-300">
                  {inspectingEnvelopeMsg.algorithm} (
                  {inspectingEnvelopeMsg.transport_mode})
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                  <div className="text-[10px] text-zinc-500">
                    SEQUENCE NUMBER
                  </div>
                  <div className="mt-1 text-white">
                    #{inspectingEnvelopeMsg.sequence_number}
                  </div>
                </div>
                <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                  <div className="text-[10px] text-zinc-500">SESSION EPOCH</div>
                  <div className="mt-1 text-white">
                    Epoch {inspectingEnvelopeMsg.session_epoch}
                  </div>
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  24-BYTE (192-BIT) EXTENDED NONCE (HEX)
                </div>
                <div className="mt-1 break-all text-sky-400">
                  {inspectingEnvelopeMsg.nonce}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  EPHEMERAL X25519 PUBLIC KEY (HEX)
                </div>
                <div className="mt-1 break-all text-emerald-400">
                  {inspectingEnvelopeMsg.ephemeral_public_key}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  AUTHENTICATED CIPHERTEXT + POLY1305 TAG (HEX)
                </div>
                <div className="mt-1 max-h-24 overflow-y-auto break-all text-zinc-300">
                  {inspectingEnvelopeMsg.ciphertext}
                </div>
              </div>

              <div className="rounded-lg border border-white/[0.06] bg-[#090a0f] p-3">
                <div className="text-[10px] text-zinc-500">
                  ED25519 TRANSCRIPT SIGNATURE (HEX)
                </div>
                <div className="mt-1 break-all text-zinc-400">
                  {inspectingEnvelopeMsg.signature}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
