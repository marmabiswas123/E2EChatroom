// chat.js (corrected)
//
// - Fixes for media handling, attachRemoteStream, hangup UI, and consistent local preview ids.
// - Keep the rest of your logic intact (data channels, encryption, file handling, private UI, etc.)

if (!(window.isSecureContext)) {
  alert("⚠️ Secure context required: Please open this site via HTTPS or localhost to enable end-to-end encryption.");
}
const socket = io();
const chatPannel = document.getElementById("chatPannel");
const log = document.getElementById("log");
const emojiButton = document.getElementById("emojiButton");
const emojiPicker = document.getElementById("emojiPicker");
const composeBar = document.getElementById("composeBar");
const fileButton = document.getElementById("fileButton");
const fileInput = document.getElementById("fileInput");
const sendButton = document.getElementById("sendButton");
const iw = window.innerWidth;

// === Config ===
// === Config ===
// Start with fallback STUN (keeps app functional if server cannot be reached)
let PEER_ICE_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];

// Fetch ExpressTURN credentials from server
async function fetchExpressTurnCreds(ttl = 3600) {
  try {
    const username = (window.USERNAME || "guest");
    const resp = await fetch(`/api/turn-credentials?user=${encodeURIComponent(username)}&ttl=${encodeURIComponent(ttl)}`, { cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    if (data && data.success && Array.isArray(data.iceServers) && data.iceServers.length) {
      PEER_ICE_SERVERS = data.iceServers;
      console.log("Loaded TURN/STUN from server:", PEER_ICE_SERVERS);
      return PEER_ICE_SERVERS;
    } else {
      console.warn("No iceServers returned from server");
    }
  } catch (err) {
    console.warn("Failed to fetch TURN credentials, using fallback STUN. Error:", err);
  }
}

// Call early on load so subsequent RTCPeerConnection() calls use the returned servers
fetchExpressTurnCreds().catch(e => console.warn("fetchExpressTurnCreds() failed:", e));
const FILE_CHUNK_SIZE = 64 * 1024; // 64 KiB chunks (adjustable)

// --- Utility helpers ---
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(b64) {
  try {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  } catch (e) {
    return new ArrayBuffer(0);
  }
}
function pemFromBase64(b64, label) {
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}
function insertAtCursor(input, text) {
  try {
    const start = input.selectionStart, end = input.selectionEnd;
    const before = input.value.substring(0, start), after = input.value.substring(end);
    input.value = before + text + after;
    input.selectionStart = input.selectionEnd = start + text.length;
    input.focus();
  } catch (e) {}
}

// Emoji UI
if (emojiButton && emojiPicker) {
  emojiButton.addEventListener("click", (e) => {
    e.stopPropagation();
    emojiPicker.style.display = emojiPicker.style.display === "none" ? "block" : "none";
  });
  document.addEventListener("click", (e) => {
    if (emojiPicker.style.display === "block" && !emojiPicker.contains(e.target)) emojiPicker.style.display = "none";
  });
  emojiPicker.addEventListener("emoji-click", (data) => {
    const emoji = data?.detail?.emoji?.unicode;
    if (emoji) insertAtCursor(composeBar, emoji);
  });
}

// File input
if (fileButton && fileInput) {
  fileButton.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    await sendPublicFile(file);
    fileInput.value = "";
  });
}

// UI: add a chat message to panel
function addMessage(msg) {
  try {
    const wrapper = document.createElement("div"); wrapper.classList.add("chat-message");
    const bubble = document.createElement("div"); bubble.classList.add("bubble");

    if (msg && msg.system) {
      bubble.classList.add("system");
      const content = document.createElement("div"); content.classList.add("text"); content.textContent = msg.message;
      bubble.appendChild(content);
    } else {
      const username = msg?.username || "unknown";
      const me = username === window.USERNAME;
      bubble.classList.add(me ? "sent" : "received");
      if (!me) {
        const userLabel = document.createElement("div"); userLabel.classList.add("username"); userLabel.textContent = username;
        bubble.appendChild(userLabel);
      }
      const content = document.createElement("div"); content.classList.add("text"); content.textContent = msg?.message ?? "";
      bubble.appendChild(content);
    }
    wrapper.appendChild(bubble);
    chatPannel.appendChild(wrapper);
    chatPannel.scrollTop = chatPannel.scrollHeight;
  } catch (e) {}
}

// --- Encryption queueing (unchanged) ---
const outboundQueue = [];
function queueOrSend(text) {
  if (window._sessionKey && window._sessionId) return encryptAndSendMessage(text);
  outboundQueue.push(text);
  socket.emit("request-current-session");
}
async function flushMessageQueue() {
  while (outboundQueue.length > 0) {
    const t = outboundQueue.shift();
    try { await encryptAndSendMessage(t); } catch (err) { outboundQueue.unshift(t); break; }
  }
}
async function importAesFromRaw(rawBytes) {
  try { return await window.crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]); }
  catch (e) { return null; }
}

// ---------- history handler ----------
socket.on("history", async (messages) => {
  if (!Array.isArray(messages) || messages.length === 0) return;
  for (const m of messages) {
    try {
      if (m && m.key && m.ciphertext && m.iv) {
        if (!window._rsaKeyPair) await generateKeyPair();
        if (!window._rsaKeyPair || !window.crypto?.subtle?.decrypt) continue;
        const encKeyBuf = base64ToArrayBuffer(m.key);
        if (!encKeyBuf || encKeyBuf.byteLength === 0) continue;
        const privateKey = window._rsaKeyPair.privateKey;
        let aesRaw;
        try { aesRaw = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encKeyBuf); }
        catch (e) { continue; }
        const aesKey = await importAesFromRaw(aesRaw);
        if (!aesKey) continue;
        const ctBuf = base64ToArrayBuffer(m.ciphertext);
        const ivBuf = base64ToArrayBuffer(m.iv);
        if (!(ctBuf && ctBuf.byteLength) || !(ivBuf && ivBuf.byteLength)) return;
        try {
          const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, aesKey, ctBuf);
          const text = new TextDecoder().decode(plainBuf);
          addMessage({ username: m.sender || m.username || "unknown", message: text, timestamp: m.timestamp });
          continue;
        } catch (e) {}
      }
      if (m && m.username && m.message) addMessage(m);
      else if (m && m.sender && m.message) addMessage({ username: m.sender, message: m.message, timestamp: m.timestamp });
    } catch (err) {}
  }
});

socket.onAny((ev, payload) => console.log('[client:recvAny]', ev, payload));

// text message incoming
socket.on("textMessage", async (msg) => {
  try {
    if (msg && msg.encrypted && msg.ciphertext && msg.iv) {
      const sid = msg.sessionId; if (!sid || sid !== window._sessionId) { socket.emit("request-current-session"); return; }
      if (!window._sessionKey) return;
      const ctBuf = base64ToArrayBuffer(msg.ciphertext); const ivBuf = base64ToArrayBuffer(msg.iv);
      if (!ctBuf.byteLength || !ivBuf.byteLength) return;
      try {
        const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, window._sessionKey, ctBuf);
        const text = new TextDecoder().decode(plainBuf);
        addMessage({ username: msg.sender || msg.username || "unknown", message: text, timestamp: msg.timestamp });
      } catch (e) {}
    } else {
      if (msg && msg.username && msg.message) addMessage(msg);
      else if (msg && msg.sender && msg.message) addMessage({ username: msg.sender, message: msg.message, timestamp: msg.timestamp });
    }
  } catch (err) {}
});

// join/left UI
socket.on("join", (newuser) => {
  try {
    const newlog = document.createElement("span"); newlog.classList.add("newlog");
    newlog.innerText = `${newuser || "Unknown"} joined the chat`;
    if (iw <= 420) chatPannel.appendChild(newlog); else log.appendChild(newlog);
  } catch (e) {}
});
socket.on("left", (username) => {
  try {
    const newlog = document.createElement("span"); newlog.classList.add("newlog");
    newlog.innerText = `${username || "Unknown"} left the chat`;
    log.appendChild(newlog);
  } catch (e) {}
});

// RSA keypair generation
async function generateKeyPair() {
  try {
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.generateKey) return;
    const kp = await window.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    window._rsaKeyPair = kp;
    const spki = await window.crypto.subtle.exportKey("spki", kp.publicKey);
    const b64 = arrayBufferToBase64(spki);
    window._publicKeyPem = pemFromBase64(b64, "PUBLIC KEY");
    if (socket && socket.connected && window._publicKeyPem) socket.emit("public-key", { publicKeyPem: window._publicKeyPem });
  } catch (e) {}
}

// session-key handling
socket.on("session-key", async (data) => {
  try {
    if (!data || !data.encryptedKey) return;
    if (!window._rsaKeyPair || !window.crypto?.subtle?.decrypt) return;
    const encryptedKeyBuffer = base64ToArrayBuffer(data.encryptedKey || "");
    const privateKey = window._rsaKeyPair.privateKey;
    let aesRaw;
    try { aesRaw = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedKeyBuffer); }
    catch (e) { return; }
    const imported = await importAesFromRaw(aesRaw);
    if (imported) { window._sessionKey = imported; window._sessionId = data.sessionId || null; flushMessageQueue(); }
  } catch (err) {}
});

// encrypt/send
async function encryptAndSendMessage(text) {
  const timestamp = Date.now();
  if (!window._sessionKey || !window._sessionId) { outboundQueue.push(text); socket.emit("request-current-session"); return; }
  try {
    const encoder = new TextEncoder(); const data = encoder.encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, window._sessionKey, data);
    const ctB64 = arrayBufferToBase64(ct); const ivB64 = arrayBufferToBase64(iv.buffer);
    socket.emit("textMessage", { encrypted: true, sessionId: window._sessionId, ciphertext: ctB64, iv: ivB64, sender: window.USERNAME, timestamp });
  } catch (e) { outboundQueue.push(text); socket.emit("request-current-session"); }
}

// send UI
if (sendButton && composeBar) {
  sendButton.addEventListener("click", async () => {
    const text = (composeBar.value || "").trim(); if (!text) return;
    try { queueOrSend(text); } catch (err) {}
    composeBar.value = "";
  });
  composeBar.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendButton.click(); } });
}

function getUsernameSafe() {
  try {
    if (typeof USERNAME !== "undefined" && USERNAME) return String(USERNAME);
    const el = document.getElementById("USERNAME") || document.querySelector("[data-username]");
    if (el) return el.dataset ? el.dataset.username || el.textContent.trim() : el.textContent.trim();
  } catch (e) {}
  return "Unknown";
}

socket.on("connect", async () => {
  if (!window.USERNAME) window.USERNAME = getUsernameSafe();
  try { await generateKeyPair(); } catch (e) {}
  if (window._publicKeyPem) socket.emit("public-key", { publicKeyPem: window._publicKeyPem });
  socket.emit("join", window.USERNAME);
  socket.emit("request-current-session");
});

// file-meta handling
socket.on("file-meta", async (meta) => {
  console.log(meta);
  try {
    if (!meta) return;
    if (meta.encrypted && meta.ciphertext && meta.iv) {
      if (!meta.sessionId || meta.sessionId !== window._sessionId) { socket.emit("request-current-session"); return; }
      if (!window._sessionKey) return;
      const ctBuf = base64ToArrayBuffer(meta.ciphertext); const ivBuf = base64ToArrayBuffer(meta.iv);
      if (!ctBuf || !ivBuf) return;
      let plainBuf;
      try { plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, window._sessionKey, ctBuf); }
      catch (e) { console.warn("Failed to decrypt incoming file:", e); return; }
      const blob = new Blob([plainBuf], { type: meta.mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const wrapper = document.createElement("div"); wrapper.classList.add("chat-message");
      const bubble = document.createElement("div"); bubble.classList.add("bubble", meta.sender === window.USERNAME ? "sent" : "received");
      if (meta.sender !== window.USERNAME) { const userLabel = document.createElement("div"); userLabel.classList.add("username"); userLabel.textContent = meta.sender || "unknown"; bubble.appendChild(userLabel); }
      const info = document.createElement("div"); info.classList.add("text");
      const a = document.createElement("a"); a.href = url; a.download = meta.filename || "file"; a.textContent = `Download ${meta.filename || "file"}`; a.style.display = "block";
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        const tmp = document.createElement("a"); tmp.style.display = "none"; tmp.href = url; tmp.download = a.download || meta.filename || "file"; document.body.appendChild(tmp); tmp.click();
        setTimeout(() => { tmp.remove(); try { URL.revokeObjectURL(url); } catch(e){} }, 1000);
      });
      info.appendChild(a); bubble.appendChild(info); wrapper.appendChild(bubble); chatPannel.appendChild(wrapper); chatPannel.scrollTop = chatPannel.scrollHeight;
      return;
    }
    if (meta && meta.filename && meta.url) {
      addMessage({ username: meta.sender || "server", message: `File available: ${meta.filename} - ${meta.url}` });
      return;
    }
  } catch (err) { console.error("file-meta handler error:", err); }
});

// sendPublicFile
async function sendPublicFile(file) {
  if (!file) return;
  if (!window._sessionKey || !window._sessionId) { alert("No session key available. Wait a moment or re-open the chat."); return; }
  const MAX_INLINE_SIZE = 10 * 1024 * 1024;
  if (file.size > MAX_INLINE_SIZE) { alert("File too large for inline upload (>10MB). Use private P2P transfer or smaller file."); return; }
  try {
    const ab = await file.arrayBuffer();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, window._sessionKey, ab);
    const ciphertextB64 = arrayBufferToBase64(ctBuf); const ivB64 = arrayBufferToBase64(iv.buffer);
    const meta = { encrypted: true, sessionId: window._sessionId, ciphertext: ciphertextB64, iv: ivB64, filename: file.name, mime: file.type || "application/octet-stream", size: file.size, sender: window.USERNAME, timestamp: Date.now(), private: false };
    console.log(meta);
    socket.emit("file-meta", meta);
  } catch (err) { console.error("sendPublicFile error:", err); alert("Failed to send file (see console)."); }
}

// ----------------- P2P / PRIVATE (data vs media separation) -----------------
const activePeers = new Map(); // username -> { pc, dc, mediaPc, mediaLocalStream, incomingChannel, buffers, iceQueue, mediaIceQueue }
const pendingIncomingOffers = new Map(); // from -> { offer, ts }
const pendingCallRequests = new Map(); // from -> { callType, ts }
const outgoingCallRequests = new Map(); // to -> callType

// Attach remote stream: accepts RTCTrackEvent or MediaStream
function attachRemoteStream(evtOrStream, peer) {
  let stream = null;
  try {
    if (!evtOrStream) {
      console.warn("attachRemoteStream called with falsy evtOrStream");
      return;
    }
    if (evtOrStream instanceof MediaStream) {
      stream = evtOrStream;
    } else if (evtOrStream.streams && evtOrStream.streams[0]) {
      stream = evtOrStream.streams[0];
    } else if (evtOrStream.track) {
      // Single track; convert to MediaStream
      stream = new MediaStream([evtOrStream.track]);
    } else {
      // maybe caller passed remoteUsername accidentally — bail
      console.warn("attachRemoteStream: unknown event object", evtOrStream);
      return;
    }

    const safePeer = String(peer || "unknown");
    const hasVideo = stream.getVideoTracks && stream.getVideoTracks().length > 0;
    const hasAudio = stream.getAudioTracks && stream.getAudioTracks().length > 0;

    if (hasVideo) {
      let videoEl = document.querySelector(`#remoteVideo-${CSS.escape(safePeer)}`);
      if (!videoEl) {
        videoEl = document.createElement("video");
        videoEl.id = `remoteVideo-${safePeer}`;
        videoEl.autoplay = true;
        videoEl.playsInline = true;
        videoEl.style.maxWidth = "320px";
        videoEl.style.borderRadius = "8px";
        const container = document.getElementById("privateWindowsContainer") || document.body;
        container.appendChild(videoEl);
      }
      // set stream
      try { videoEl.srcObject = stream; } catch (e) { console.warn("srcObject attach failed", e); }
      return;
    }

    if (hasAudio && !hasVideo) {
      let audioEl = document.querySelector(`#remoteAudio-${CSS.escape(safePeer)}`);
      if (!audioEl) {
        audioEl = document.createElement("audio");
        audioEl.id = `remoteAudio-${safePeer}`;
        audioEl.autoplay = true;
        audioEl.controls = false;
        const container = document.getElementById("privateWindowsContainer") || document.body;
        container.appendChild(audioEl);
      }
      try { audioEl.srcObject = stream; } catch (e) { console.warn("srcObject attach failed", e); }
      return;
    }

    // fallback: attach as video element
    let fallback = document.querySelector(`#remoteVideo-${CSS.escape(safePeer)}`);
    if (!fallback) {
      fallback = document.createElement("video");
      fallback.id = `remoteVideo-${safePeer}`;
      fallback.autoplay = true;
      fallback.playsInline = true;
      const container = document.getElementById("privateWindowsContainer") || document.body;
      container.appendChild(fallback);
    }
    try { fallback.srcObject = stream; } catch (e) { console.warn("srcObject attach failed", e); }
  } catch (err) {
    console.error("attachRemoteStream failed:", err);
  }
}

function createPeerConnection(remoteUsername) {
  const pc = new RTCPeerConnection({ iceServers: PEER_ICE_SERVERS });
  pc.remoteUsername = remoteUsername;

  pc.onicecandidate = (ev) => {
    if (ev.candidate) socket.emit("webrtc-ice", { to: remoteUsername, candidate: ev.candidate, media: false });
  };
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === "disconnected" || pc.connectionState === "failed" || pc.connectionState === "closed") {
      const ap = activePeers.get(remoteUsername) || {};
      if (!ap.pc && !ap.mediaPc && !ap.dc && !ap.incomingChannel) activePeers.delete(remoteUsername);
    }
  };
  pc.ondatachannel = (ev) => {
    const ch = ev.channel;
    console.log("ondatachannel from", remoteUsername, ch.label);
    handleIncomingDataChannel(remoteUsername, ch);
  };
  // If the data PC ever receives tracks (unexpected), attach them safely
  pc.ontrack = (evt) => {
    attachRemoteStream(evt, remoteUsername);
  };
  return pc;
}

function createMediaConnection(remoteUsername) {
  const pc = new RTCPeerConnection({ iceServers: PEER_ICE_SERVERS });
  pc.remoteUsername = remoteUsername;

  pc.ontrack = (evt) => {
    // attach tracks to UI
    attachRemoteStream(evt, remoteUsername);
  };

  pc.onicecandidate = (ev) => {
    if (ev.candidate) socket.emit("webrtc-ice", { to: remoteUsername, candidate: ev.candidate, media: true });
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === "disconnected" || pc.connectionState === "failed" || pc.connectionState === "closed") {
      const ap = activePeers.get(remoteUsername) || {};
      if (ap && ap.mediaPc === pc) {
        delete ap.mediaPc;
        activePeers.set(remoteUsername, ap);
        updateHangupButton(remoteUsername, false);
      }
    }
  };

  return pc;
}

// Wait for datachannel to open
function waitForDataChannelOpen(ch, timeout = 60000) {
  return new Promise((resolve, reject) => {
    if (!ch) return reject(new Error("No DataChannel"));
    if (ch.readyState === "open") return resolve();
    const onOpen = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error("DataChannel closed")); };
    const onError = (err) => { cleanup(); reject(err || new Error("DataChannel error")); };
    const timer = setTimeout(() => { cleanup(); reject(new Error("DataChannel open timeout")); }, timeout);
    function cleanup() {
      clearTimeout(timer);
      ch.removeEventListener("open", onOpen);
      ch.removeEventListener("close", onClose);
      ch.removeEventListener("error", onError);
    }
    ch.addEventListener("open", onOpen);
    ch.addEventListener("close", onClose);
    ch.addEventListener("error", onError);
  });
}

// enable private UI when DC open
function enablePrivateUI(username) {
  const chat = privateChats.get(username);
  if (!chat) return;
  if (chat.sendBtn) chat.sendBtn.disabled = false;
  if (chat.fileInputEl) chat.fileInputEl.disabled = false;
}

// setup outbound DC for data
function setupOutboundDataChannel(targetUsername, dc) {
  dc.onopen = () => {
    console.log("DataChannel open ->", targetUsername);
    const ap = activePeers.get(targetUsername) || {};
    ap.dc = dc;
    activePeers.set(targetUsername, ap);
    enablePrivateUI(targetUsername);
  };
  dc.onclose = () => { console.log("DataChannel closed", targetUsername); };
  dc.onerror = (e) => console.error("DC error", e);
  dc.onmessage = (ev) => handleDataMessage(targetUsername, ev.data);
}
function handleIncomingDataChannel(remoteUsername, channel) {
  channel.binaryType = "arraybuffer";
  channel.onopen = () => {
    console.log("Incoming DC open from", remoteUsername);
    const ap = activePeers.get(remoteUsername) || {};
    ap.incomingChannel = channel;
    activePeers.set(remoteUsername, ap);
    enablePrivateUI(remoteUsername);
  };
  channel.onmessage = (ev) => handleDataMessage(remoteUsername, ev.data);
  channel.onclose = () => console.log("Incoming DC closed", remoteUsername);

  const ap = activePeers.get(remoteUsername) || {};
  ap.incomingChannel = channel;
  activePeers.set(remoteUsername, ap);
}

// startPrivateP2P (caller creates data PC + DC)
async function startPrivateP2P(targetUsername) {
  if (!targetUsername) return;
  if (activePeers.has(targetUsername)) {
    return activePeers.get(targetUsername);
  }

  const pc = createPeerConnection(targetUsername);
  const dc = pc.createDataChannel("messaging", { ordered: true, maxRetransmits: null });
  dc.binaryType = "arraybuffer";
  setupOutboundDataChannel(targetUsername, dc);

  const ap = { pc, dc, mediaPc: null, mediaLocalStream: null, incomingChannel: null, buffers: {}, iceQueue: [], mediaIceQueue: [] };
  activePeers.set(targetUsername, ap);

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit("webrtc-offer", { to: targetUsername, offer: pc.localDescription, media: false });
  } catch (e) {
    console.error("startPrivateP2P createOffer/setLocal failed", e);
    throw e;
  }
  return ap;
}

// ----------------- SIGNALLING HANDLERS -----------------

// Received offer (data or media)
socket.on("webrtc-offer", async (data) => {
  const { from, offer, media, callType } = data || {};
  if (!from || !offer) return;

  // ---- Media (call) offer handling (caller receives offer created by callee who accepted a call request) ----
  if (media) {
    let ap = activePeers.get(from) || { pc: null, dc: null, mediaPc: null, incomingChannel: null, buffers: {}, iceQueue: [], mediaIceQueue: [] };
    if (!ap.mediaPc) {
      ap.mediaPc = createMediaConnection(from);
      activePeers.set(from, ap);
    } else {
      activePeers.set(from, ap);
    }

    try {
      // set remote description (offer)
      await ap.mediaPc.setRemoteDescription(new RTCSessionDescription(offer));

      // detect if remote wants video
      const wantsVideo = (callType === "video") || sdpHasVideo(offer);

      // Request local media if available (caller should provide mic/camera)
      let localStream = null;
      try {
        const constraints = { audio: true };
        if (wantsVideo) constraints.video = { facingMode: "user" };
        localStream = await navigator.mediaDevices.getUserMedia(constraints);
      } catch (err) {
        console.warn("getUserMedia when receiving media offer failed:", err);
        localStream = null;
      }

      if (localStream) {
        ap.mediaLocalStream = localStream;
        localStream.getTracks().forEach(t => ap.mediaPc.addTrack(t, localStream));
        // only show local preview when camera/video track exists
        if (localStream.getVideoTracks && localStream.getVideoTracks().length > 0) {
        attachLocalPreview(localStream);
        }
      }

      // create answer and send back
      const answer = await ap.mediaPc.createAnswer();
      await ap.mediaPc.setLocalDescription(answer);

      socket.emit("webrtc-answer", { to: from, answer: ap.mediaPc.localDescription, media: true, callType: (wantsVideo ? 'video' : 'audio') });

      // flush queued media ICE candidates
      if (ap.mediaIceQueue && ap.mediaIceQueue.length) {
        for (const c of ap.mediaIceQueue) {
          try { await ap.mediaPc.addIceCandidate(new RTCIceCandidate(c)); } catch (e) { console.warn("flushing media ICE candidate failed", e); }
        }
        ap.mediaIceQueue = [];
        activePeers.set(from, ap);
      }

      // show hangup UI
      showHangupForPeer(from, true);
    } catch (err) {
      console.error("Failed handling media offer:", err);
      alert("Failed to handle incoming call: " + (err && err.message ? err.message : err));
    }

    return;
  }

  // ---- Non-media (data) offer handling ----
  // keep your existing flow: create data PC, setRemoteDescription, createAnswer, setLocalDescription, emit webrtc-answer
  // Accept a data-channel offer (private chat request)
  try {
    const pc = createPeerConnection(from);
    const ap = { pc, dc: null, mediaPc: null, incomingChannel: null, buffers: {}, iceQueue: [], mediaIceQueue: [] };
    activePeers.set(from, ap);

    // show private UI
    pendingIncomingOffers.set(from, { offer, ts: Date.now() });
    unseenPrivateNotify = true;
    renderPrivateBadge();
  } catch (e) {
    console.error("Error handling data offer", e);
  }
});

function sdpHasVideo(offer) {
  try {
    if (!offer || !offer.sdp) return false;
    return /\bm=video\b/i.test(offer.sdp);
  } catch (e) { return false; }
}

// Received answer (from callee after they created offer)
socket.on("webrtc-answer", async (data) => {
  const { from, answer, media } = data || {};
  if (!from || !answer) return;
  const ap = activePeers.get(from);
  if (!ap) return;

  try {
    if (media) {
      // media answer -> set on mediaPc
      if (!ap.mediaPc) {
        console.warn("Received media answer but no mediaPc exists yet for", from);
        // optionally create one, but we expect mediaPc to exist
        return;
      }
      await ap.mediaPc.setRemoteDescription(new RTCSessionDescription(answer));
      // flush queued media ICE candidates
      if (ap.mediaIceQueue && ap.mediaIceQueue.length) {
        for (const c of ap.mediaIceQueue) {
          try { await ap.mediaPc.addIceCandidate(new RTCIceCandidate(c)); }
          catch (e) { console.warn("flushing media ICE candidate failed", e); }
        }
        ap.mediaIceQueue = [];
        activePeers.set(from, ap);
      }
      return;
    }

    // non-media/data answer
    if (ap && ap.pc) {
      await ap.pc.setRemoteDescription(new RTCSessionDescription(answer));
      // flush queued ICE if present
      if (ap.iceQueue && ap.iceQueue.length) {
        for (const c of ap.iceQueue) {
          try { await ap.pc.addIceCandidate(new RTCIceCandidate(c)); }
          catch (e) { console.warn("flushing ICE candidate failed", e); }
        }
        ap.iceQueue = [];
        activePeers.set(from, ap);
      }
    }
  } catch (e) {
    console.error("setRemoteDescription failed for answer", e);
  }
});

// ICE candidate handler - route media vs data
socket.on("webrtc-ice", async (data) => {
  const { from, candidate, media } = data || {};
  if (!from || !candidate) return;
  let ap = activePeers.get(from);
  if (!ap) {
    // create placeholder to queue ICE until pc/mediaPc exists
    ap = { pc: null, dc: null, mediaPc: null, incomingChannel: null, buffers: {}, iceQueue: [], mediaIceQueue: [] };
    activePeers.set(from, ap);
  }

  if (media) {
    if (ap.mediaPc && ap.mediaPc.remoteDescription) {
      try { await ap.mediaPc.addIceCandidate(new RTCIceCandidate(candidate)); }
      catch (e) { console.warn("addIceCandidate failed for mediaPc", e); }
    } else {
      ap.mediaIceQueue = ap.mediaIceQueue || [];
      ap.mediaIceQueue.push(candidate);
      activePeers.set(from, ap);
    }
    return;
  }

  // non-media ICE (existing flow)
  if (ap.pc && ap.pc.remoteDescription) {
    try { await ap.pc.addIceCandidate(new RTCIceCandidate(candidate)); }
    catch (e) { console.warn("addIceCandidate failed", e); }
  } else {
    ap.iceQueue = ap.iceQueue || [];
    ap.iceQueue.push(candidate);
    activePeers.set(from, ap);
  }
});

// Accept pending incoming data offer (manual)
async function acceptIncomingOffer(from) {
  const record = pendingIncomingOffers.get(from);
  if (!record || !record.offer) {
    console.warn("No offer to accept from", from);
    pendingIncomingOffers.delete(from);
    renderPrivateBadge();
    return;
  }
  const offer = record.offer;
  pendingIncomingOffers.delete(from);
  renderPrivateBadge();

  const pc = createPeerConnection(from);
  const ap = { pc, dc: null, mediaPc: null, incomingChannel: null, buffers: {}, iceQueue: [] };
  activePeers.set(from, ap);

  openPrivateChat(from, false); // show UI

  try {
    await pc.setRemoteDescription(new RTCSessionDescription(offer));

    // flush pending data ICE if any
    if (ap.iceQueue && ap.iceQueue.length) {
      for (const cand of ap.iceQueue) {
        try { await pc.addIceCandidate(new RTCIceCandidate(cand)); } catch (e) { console.warn("flush addIceCandidate failed", e); }
      }
      ap.iceQueue = [];
      activePeers.set(from, ap);
    }

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit("webrtc-answer", { to: from, answer: pc.localDescription, media: false });
  } catch (e) {
    console.error("acceptIncomingOffer failed", e);
    alert("Failed to accept the private offer: " + (e && e.message ? e.message : e));
  }
}

// Data message handler
function handleDataMessage(remoteUsername, data) {
  if (typeof data === "string") {
    let obj;
    try { obj = JSON.parse(data); } catch (e) { console.warn("Invalid DC JSON", e); return; }
    const ap = activePeers.get(remoteUsername);
    if (!ap) {
      console.warn("No active peer for DC message from", remoteUsername);
      return;
    }
    if (obj.type === "text") {
      appendPrivateMessage(remoteUsername, remoteUsername, obj.text, false);
    } else if (obj.type === "file-start") {
      ap.buffers = ap.buffers || {};
      ap.buffers[obj.id] = { chunks: [], filename: obj.filename, size: obj.size, mime: obj.mime, received: 0 };
      activePeers.set(remoteUsername, ap);
    } else if (obj.type === "file-end") {
      const meta = ap.buffers && ap.buffers[obj.id];
      if (!meta) return;
      const blob = new Blob(meta.chunks, { type: meta.mime || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      try {
        const wrapper = document.createElement("div"); wrapper.classList.add("chat-message");
        const bubble = document.createElement("div"); bubble.classList.add("bubble");
        bubble.classList.add(remoteUsername === window.USERNAME ? "sent" : "received");
        if (remoteUsername !== window.USERNAME) {
          const userLabel = document.createElement("div"); userLabel.classList.add("username"); userLabel.textContent = remoteUsername; bubble.appendChild(userLabel);
        }
        const info = document.createElement("div"); info.classList.add("text");
        const a = document.createElement("a"); a.href = url; a.download = meta.filename || "file"; a.textContent = `Download ${meta.filename || "file"}`; a.style.display = "block";
        a.addEventListener("click", (ev) => {
          ev.preventDefault();
          const tmp = document.createElement("a");
          tmp.style.display = "none";
          tmp.href = url;
          tmp.download = a.download || meta.filename || "file";
          document.body.appendChild(tmp);
          tmp.click();
          setTimeout(() => { tmp.remove(); try { URL.revokeObjectURL(url); } catch(e){} }, 1000);
        });
        info.appendChild(a);
        const metaLine = document.createElement("div"); metaLine.style.fontSize = "0.8em"; metaLine.style.opacity = "0.85"; metaLine.textContent = `${(meta.size || 0)} bytes`;
        info.appendChild(metaLine);
        bubble.appendChild(info); wrapper.appendChild(bubble);
        if (privateChats.has(remoteUsername)) {
          privateChats.get(remoteUsername).messagesEl.appendChild(wrapper);
          privateChats.get(remoteUsername).messagesEl.scrollTop = privateChats.get(remoteUsername).messagesEl.scrollHeight;
        } else {
          chatPannel.appendChild(wrapper);
          chatPannel.scrollTop = chatPannel.scrollHeight;
        }
      } catch (e) {
        console.error("Error rendering received file link:", e);
      } finally {
        delete ap.buffers[obj.id];
        activePeers.set(remoteUsername, ap);
      }
    }
    return;
  }

  // binary chunk
  const arrBuf = data;
  const ap = activePeers.get(remoteUsername);
  if (!ap) return;
  const keys = Object.keys(ap.buffers || {});
  if (keys.length === 0) { console.warn("Unexpected binary chunk without file-start"); return; }
  const id = keys[0]; const meta = ap.buffers[id]; meta.chunks.push(arrBuf); meta.received += arrBuf.byteLength || 0; activePeers.set(remoteUsername, ap);
}

// Private send helpers
async function sendPrivateText(targetUsername, text) {
  const ap = activePeers.get(targetUsername);
  if (!ap) { alert("No P2P session. Start a private chat first."); return; }

  const ch = (ap.dc && ap.dc.readyState === "open") ? ap.dc : (ap.incomingChannel && ap.incomingChannel.readyState === "open" ? ap.incomingChannel : null);
  if (!ch) {
    const candidate = ap.dc || ap.incomingChannel;
    if (!candidate) { alert("No datachannel yet. Waiting for connection..."); return; }
    try { await waitForDataChannelOpen(candidate, 60000); } catch (e) { alert("DataChannel did not open. Try again."); return; }
  }
  const finalCh = (ap.dc && ap.dc.readyState === "open") ? ap.dc : ap.incomingChannel;
  if (!finalCh || finalCh.readyState !== "open") { alert("DataChannel still not open"); return; }
  finalCh.send(JSON.stringify({ type: "text", text, ts: Date.now() }));
  appendPrivateMessage(targetUsername, window.USERNAME, text, true);
}

async function sendFileP2P(targetUsername, file) {
  if (!file) return;
  const ap = activePeers.get(targetUsername);
  if (!ap) { alert("No peer. Start a P2P session first."); return; }
  const ch = (ap.dc && ap.dc.readyState) ? ap.dc : ap.incomingChannel;
  if (!ch) { alert("No datachannel available"); return; }

  try {
    await waitForDataChannelOpen(ch, 60000);
    try { ch.bufferedAmountLowThreshold = FILE_CHUNK_SIZE * 4; } catch (e) {}
    const id = `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
    ch.send(JSON.stringify({ type: "file-start", id, filename: file.name, size: file.size, mime: file.type }));
    let offset = 0; const total = file.size;
    while (offset < total) {
      const slice = file.slice(offset, offset + FILE_CHUNK_SIZE);
      const ab = await slice.arrayBuffer();
      ch.send(ab);
      offset += ab.byteLength;
      while (ch.bufferedAmount > FILE_CHUNK_SIZE * 8) await new Promise(r => setTimeout(r, 50));
    }
    ch.send(JSON.stringify({ type: "file-end", id }));
  } catch (err) { console.error("sendFileP2P error:", err); alert("Failed to send file via P2P: " + (err && err.message ? err.message : "unknown")); }
}

// ----------------- PRIVATE UI -----------------
const goPrivateBtn = document.getElementById("goPrivateBtn");
const goPrivateBadge = document.getElementById("goPrivateBadge");
const privateMenu = document.getElementById("privateMenu");
const privateUserList = document.getElementById("privateUserList");
const privateWindowsContainer = document.getElementById("privateWindowsContainer");

const privateChats = new Map(); // username -> { container, messagesEl, inputEl, fileInputEl, sendBtn }
let unseenPrivateNotify = false;

if (goPrivateBtn && privateMenu) {
  goPrivateBtn.addEventListener("click", () => {
    if (privateMenu.style.display === "block") { privateMenu.style.display = "none"; }
    else { privateMenu.style.display = "block"; socket.emit("list-users"); unseenPrivateNotify = false; goPrivateBadge.style.display = "none"; }
  });
  document.addEventListener("click", (e) => {
    if (privateMenu.style.display === "block" && !privateMenu.contains(e.target) && e.target !== goPrivateBtn) privateMenu.style.display = "none";
  });
}

// Render active user list
socket.on("active-users", (users) => {
  if (!Array.isArray(users)) return;
  privateUserList.innerHTML = "";

  users.forEach(u => {
    if (u === window.USERNAME) return;

    const row = document.createElement("div");
    row.classList.add("privateUser");
    row.textContent = u;

    const actions = document.createElement("div");

    // PM button
    const pmBtn = document.createElement("button"); pmBtn.textContent = "PM";
    pmBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openPrivateChat(u, true);
      privateMenu.style.display = "none";
    });

    // Audio call button
    const callBtn = document.createElement("button"); callBtn.textContent = "Call";
    callBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      outgoingCallRequests.set(u, 'audio');
      socket.emit("private-call-request", { to: u, callType: 'audio' });
      alert("Call request sent");
      privateMenu.style.display = "none";
    });

    // Video call button
    const videoBtn = document.createElement("button"); videoBtn.textContent = "Video";
    videoBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      outgoingCallRequests.set(u, 'video');
      socket.emit("private-call-request", { to: u, callType: 'video' });
      alert("Video call request sent");
      privateMenu.style.display = "none";
    });

    actions.appendChild(pmBtn);
    actions.appendChild(callBtn);
    actions.appendChild(videoBtn);
    row.appendChild(actions);
    privateUserList.appendChild(row);
  });

  // pending call requests
  pendingCallRequests.forEach((entry, from) => {
    const row = document.createElement("div");
    row.classList.add("privateUser");
    row.innerHTML = `<strong>${from}</strong> wants to ${entry.callType} call`;
    const acceptBtn = document.createElement("button");
    acceptBtn.textContent = "Accept";
    acceptBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      privateMenu.style.display = "none";
      acceptCallRequest(from);
    });
    const rejectBtn = document.createElement("button");
    rejectBtn.textContent = "Reject";
    rejectBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      pendingCallRequests.delete(from);
      socket.emit("webrtc-offer-reject", { to: from });
      renderPrivateBadge();
      privateUserList.removeChild(row);
    });
    row.appendChild(acceptBtn);
    row.appendChild(rejectBtn);
    privateUserList.appendChild(row);
  });

  // pending SDP offers
  pendingIncomingOffers.forEach((entry, from) => {
    const row = document.createElement("div");
    row.classList.add("privateUser");
    row.innerHTML = `<strong>${from}</strong> sent a private chat request`;
    const acceptBtn = document.createElement("button");
    acceptBtn.textContent = "Accept";
    acceptBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      privateMenu.style.display = "none";
      acceptIncomingOffer(from);
    });
    const rejectBtn = document.createElement("button");
    rejectBtn.textContent = "Reject";
    rejectBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      pendingIncomingOffers.delete(from);
      socket.emit("webrtc-offer-reject", { to: from });
      renderPrivateBadge();
      privateUserList.removeChild(row);
    });
    row.appendChild(acceptBtn);
    row.appendChild(rejectBtn);
    privateUserList.appendChild(row);
  });
});

// Call request handler (callee receives)
socket.on("private-call-request", (data) => {
  const { from, callType } = data || {};
  if (!from) return;
  pendingCallRequests.set(from, { callType: callType || "audio", ts: Date.now() });
  unseenPrivateNotify = true; renderPrivateBadge();
});

function renderPrivateBadge() {
  if (unseenPrivateNotify || pendingIncomingOffers.size > 0 || pendingCallRequests.size > 0) goPrivateBadge.style.display = "inline-block";
  else goPrivateBadge.style.display = "none";
}

// Accept call request (callee flow -> create mediaPc, add mic, create offer and send to caller)
async function acceptCallRequest(from) {
  const entry = pendingCallRequests.get(from);
  if (!entry) return;
  pendingCallRequests.delete(from);
  renderPrivateBadge();

  const mediaPc = createMediaConnection(from);
  const ap = activePeers.get(from) || { pc: null, dc: null, mediaPc: null, incomingChannel: null, buffers: {}, iceQueue: [], mediaIceQueue: [] };
  ap.mediaPc = mediaPc;
  activePeers.set(from, ap);

  // get local media
  const constraints = { audio: true };
  if (entry.callType === 'video') constraints.video = true;
  let stream = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia(constraints);
    ap.mediaLocalStream = stream;
    stream.getTracks().forEach(t => mediaPc.addTrack(t, stream));
    // local preview
     if (stream.getVideoTracks && stream.getVideoTracks().length > 0) {
       attachLocalPreview(stream);
      }
  } catch (e) {
    console.warn("getUserMedia failed for call accept (continuing without local media):", e);
  }

  try {
    const offer = await mediaPc.createOffer();
    await mediaPc.setLocalDescription(offer);
    socket.emit("webrtc-offer", { to: from, offer: mediaPc.localDescription, media: true, callType: entry.callType ? 'video' : 'audio' });
    updateHangupButton(from, true);
  } catch (e) {
    console.error("acceptCallRequest error", e);
    alert("Failed to accept call request: " + (e && e.message ? e.message : e));
  }
}


// local preview helper
function attachLocalPreview(stream) {
  let el = document.getElementById("localPreview");
  if (!el) {
    el = document.createElement("video");
    el.id = "localPreview";
    el.muted = true;
    el.autoplay = true;
    el.playsInline = true;
    el.style.maxWidth = "120px";
    el.style.borderRadius = "6px";
    const container = document.getElementById("privateWindowsContainer") || document.body;
    container.appendChild(el);
  }
  try { el.srcObject = stream; } catch (e) { console.warn("attachLocalPreview fallback:", e); }
}

// Hangup: only closes media side (keeps datachannels alive)
function hangupPrivate(username, notifyRemote = true) {
  const ap = activePeers.get(username);
  if (!ap) return;

  // stop local media tracks
  if (ap.mediaLocalStream) {
    try { ap.mediaLocalStream.getTracks().forEach(t => { try { t.stop(); } catch(e){} }); } catch(e){}
    delete ap.mediaLocalStream;
  }

  // close only the media PeerConnection
  if (ap.mediaPc) {
    try { ap.mediaPc.close(); } catch (e) {}
    delete ap.mediaPc;
  }

  // remove remote UI elements created for media
  const audioEl = document.getElementById(`remoteAudio-${username}`); if (audioEl) audioEl.remove();
  const videoEl = document.getElementById(`remoteVideo-${username}`); if (videoEl) videoEl.remove();
  const localPreview = document.getElementById(`localPreview`); if (localPreview) localPreview.remove();

  // keep datachannel & data pc untouched
  activePeers.set(username, ap);

  // notify peer so they can cleanup their media side
  if (notifyRemote) {
    try { socket.emit("webrtc-hangup", { to: username, media: true }); }
    catch (e) { console.warn("Failed to emit webrtc-hangup:", e); }
  }

  updateHangupButton(username, false);
}

// remote hangup handler: cleanup local media (do not re-emit)
socket.on("webrtc-hangup", (data) => {
  const from = data?.from;
  if (!from) return;
  doLocalHangupCleanup(from);
});

// user clicked hangup in UI
function userHangupPeer(username) {
  hangupPrivate(username, true);
}

// do local-only cleanup (no emitting)
function doLocalHangupCleanup(username) {
  const ap = activePeers.get(username);
  if (!ap) return;

  if (ap.mediaPc) {
    try { ap.mediaPc.close(); } catch (e) {}
    ap.mediaPc = null;
  }
  if (ap.mediaLocalStream) {
    try { ap.mediaLocalStream.getTracks().forEach(t => t.stop()); } catch(e){}
    ap.mediaLocalStream = null;
  }
  showHangupForPeer(username, false);
  removeRemoteElements(username);
  activePeers.set(username, ap);
}

function removeRemoteElements(username) {
  const audioEl = document.getElementById(`remoteAudio-${username}`); if (audioEl) audioEl.remove();
  const videoEl = document.getElementById(`remoteVideo-${username}`); if (videoEl) videoEl.remove();
  const localPreview = document.getElementById(`localPreview`); if (localPreview) localPreview.remove();
}

// show/hide hangup button in private window UI
function showHangupForPeer(peer, visible) {
  let btn = document.getElementById(`hangup-${CSS.escape(peer)}`);
  if (!btn && visible) {
    btn = document.createElement("button");
    btn.id = `hangup-${peer}`;
    btn.className = "hangupBtn";
    btn.addEventListener("click", () => {
      socket.emit("webrtc-hangup", { to: peer });
      // stop media tracks locally
      const ap = activePeers.get(peer);
      if (ap && ap.mediaLocalStream) {
        ap.mediaLocalStream.getTracks().forEach(t => t.stop());
        delete ap.mediaLocalStream;
        activePeers.set(peer, ap);
      }
      if (btn) btn.style.display = "none";
      const del1 = document.getElementById(`remoteVideo-${peer}`);
      const del2 = document.getElementById("localPreview");
      try{
      del1.remove();
      del2.remove();
      }
      catch(e){

      }
    });
    const container = document.getElementById("privateWindowsContainer") || document.body;
    const btnIco = document.createElement("img");
    btnIco.id="hangupIco";
    btnIco.src="icons/hangup_icon.svg"
    btn.appendChild(btnIco);
    container.appendChild(btn);
  }
  if (btn) btn.style.display = visible ? "inline-block" : "none";
}
function updateHangupButton(username, show) {
  showHangupForPeer(username, show);
}

// Expose acceptIncomingOffer to global (old UI used it)
window.acceptIncomingOffer = acceptIncomingOffer;

// Create/bring-to-front a private chat window (keeps hangup button and call buttons local)
function openPrivateChat(username, initiateP2P = false) {
  if (privateChats.has(username)) {
    const c = privateChats.get(username).container; c.style.display = "flex"; return privateChats.get(username);
  }

  const win = document.createElement("div"); win.classList.add("privateWindow");
  const header = document.createElement("div"); header.classList.add("pw-header"); header.innerHTML = `<span>${username}</span>`;
  const headerActions = document.createElement("div");

  const hangupBtn = document.createElement("button");
  hangupBtn.setAttribute('data-hangup', '1');
  hangupBtn.title = "Hang up";
  hangupBtn.style.display = "none"; // hidden until in-call
  hangupBtn.classList.add("hangupBtn");
  hangupBtn.addEventListener("click", () => userHangupPeer(username));

  const callBtn = document.createElement("button"); callBtn.textContent = "📞"; callBtn.title = "Request audio call";
  callBtn.addEventListener("click", () => {
    outgoingCallRequests.set(username, 'audio');
    socket.emit("private-call-request", { to: username, callType: 'audio' });
    alert("Call request sent");
  });

  const videoBtn = document.createElement("button"); videoBtn.textContent = "🎥"; videoBtn.title = "Request video call";
  videoBtn.addEventListener("click", () => {
    outgoingCallRequests.set(username, 'video');
    socket.emit("private-call-request", { to: username, callType: 'video' });
    alert("Video call request sent");
  });

  const closeBtn = document.createElement("button"); closeBtn.textContent = "✖";
  closeBtn.addEventListener("click", () => {
    hangupPrivate(username); // stop media if any
    win.remove();
    privateChats.delete(username);
  });

  headerActions.appendChild(hangupBtn); headerActions.appendChild(callBtn); headerActions.appendChild(videoBtn); headerActions.appendChild(closeBtn);
  header.appendChild(headerActions);

  const body = document.createElement("div"); body.classList.add("pw-body"); body.innerHTML = "";
  const compose = document.createElement("div"); compose.classList.add("pw-compose");
  const input = document.createElement("input"); input.type = "text"; input.placeholder = "Message";
  const sendBtn = document.createElement("button"); sendBtn.textContent = "Send"; sendBtn.disabled = true;
  sendBtn.addEventListener("click", () => {
    const t = input.value.trim(); if (!t) return;
    sendPrivateText(username, t);
    input.value = "";
  });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") sendBtn.click(); });

  const fbtn = document.createElement("button"); fbtn.classList.add("pw-file-btn"); fbtn.textContent = "📎";
  const finp = document.createElement("input"); finp.type = "file"; finp.style.display = "none"; finp.disabled = true;
  finp.addEventListener("change", (ev) => {
    const file = finp.files && finp.files[0]; if (!file) return;
    sendFileP2P(username, file); appendPrivateMessage(username, window.USERNAME, `Sent file: ${file.name}`, true); finp.value = "";
  });
  fbtn.addEventListener("click", () => finp.click());

  compose.appendChild(input); compose.appendChild(sendBtn); compose.appendChild(fbtn); compose.appendChild(finp);
  win.appendChild(header); win.appendChild(body); win.appendChild(compose);
  privateWindowsContainer.appendChild(win);

  privateChats.set(username, { container: win, messagesEl: body, inputEl: input, fileInputEl: finp, sendBtn });

  // If caller requested PM, initiate DC
  if (initiateP2P) {
    startPrivateP2P(username).then((ap) => {
      const maybeDc = ap?.dc || activePeers.get(username)?.dc;
      if (maybeDc) {
        waitForDataChannelOpen(maybeDc, 60000).then(() => {
          console.log("P2P datachannel opened to", username);
        }).catch((err) => {
          console.warn("DC did not open in 60s for", username, err);
        });
      } else {
        console.warn("No DC created for", username);
      }
    }).catch(err => console.warn("startPrivateP2P failed", err));
  }

  return privateChats.get(username);
}

// Append message into private window
function appendPrivateMessage(targetUsername, who, text, me=false) {
  if (!privateChats.has(targetUsername)) openPrivateChat(targetUsername, false);
  const wrapper = document.createElement("div"); wrapper.style.margin = "6px 0";
  wrapper.innerHTML = `<div style="font-weight:600">${who}</div><div>${text}</div>`;
  privateChats.get(targetUsername).messagesEl.appendChild(wrapper);
  privateChats.get(targetUsername).messagesEl.scrollTop = privateChats.get(targetUsername).messagesEl.scrollHeight;
}
