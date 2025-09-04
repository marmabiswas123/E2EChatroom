// chat.js — fixed (replace whole file)
const socket = io();
const chatPannel = document.getElementById("chatPannel");
const log = document.getElementById("log");
const emojiButton = document.getElementById("emojiButton");
const emojiPicker = document.getElementById("emojiPicker");
const composeBar = document.getElementById("composeBar");
const sendButton = document.getElementById("sendButton");

// Emoji handlers
if (emojiButton && emojiPicker) {
  emojiButton.addEventListener("click", (e) => {
    e.stopPropagation();
    emojiPicker.style.display = emojiPicker.style.display === "none" ? "block" : "none";
  });
  document.addEventListener("click", (e) => {
    if (emojiPicker.style.display === "block" && !emojiPicker.contains(e.target)) {
      emojiPicker.style.display = "none";
    }
  });
  emojiPicker.addEventListener("emoji-click", (data) => {
    const emoji = data?.detail?.emoji?.unicode;
    if (emoji) insertAtCursor(composeBar, emoji);
  });
}
function insertAtCursor(input, text) {
  try {
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const before = input.value.substring(0, start);
    const after = input.value.substring(end);
    input.value = before + text + after;
    input.selectionStart = input.selectionEnd = start + text.length;
    input.focus();
  } catch (e) {}
}

// base64 helpers
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

// UI rendering
function addMessage(msg) {
  try {
    const wrapper = document.createElement("div");
    wrapper.classList.add("chat-message");

    const bubble = document.createElement("div");
    bubble.classList.add("bubble");

    if (msg && msg.system) {
      bubble.classList.add("system");
      const content = document.createElement("div");
      content.classList.add("text");
      content.textContent = msg.message;
      bubble.appendChild(content);
    } else {
      const username = msg?.username || "unknown";
      const me = username === window.USERNAME;
      bubble.classList.add(me ? "sent" : "received");
      if (!me) {
        const userLabel = document.createElement("div");
        userLabel.classList.add("username");
        userLabel.textContent = username;
        bubble.appendChild(userLabel);
      }
      const content = document.createElement("div");
      content.classList.add("text");
      content.textContent = msg?.message ?? "";
      bubble.appendChild(content);
    }

    wrapper.appendChild(bubble);
    chatPannel.appendChild(wrapper);
    chatPannel.scrollTop = chatPannel.scrollHeight;
  } catch (e) {}
}

// outbound queue
const outboundQueue = [];
function queueOrSend(text) {
  if (window._sessionKey && window._sessionId) return encryptAndSendMessage(text);
  outboundQueue.push(text);
  socket.emit("request-current-session");
}
async function flushMessageQueue() {
  while (outboundQueue.length > 0) {
    const t = outboundQueue.shift();
    try {
      await encryptAndSendMessage(t);
    } catch (err) {
      outboundQueue.unshift(t);
      break;
    }
  }
}

// import AES key raw
async function importAesFromRaw(rawBytes) {
  try {
    return await window.crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  } catch (e) {
    return null;
  }
}

// ---------- History handler (decrypt stored key + ciphertext per-item) ----------
socket.on("history", async (messages) => {
  if (!Array.isArray(messages) || messages.length === 0) return;

  for (const m of messages) {
    try {
      // if history item has encrypted key (server encrypted the session key with our public key)
      if (m && m.key && m.ciphertext && m.iv) {
        // ensure we have RSA keypair
        if (!window._rsaKeyPair) {
          await generateKeyPair();
        }
        if (!window._rsaKeyPair || !window.crypto?.subtle?.decrypt) {
          // cannot decrypt keys on this client
          continue;
        }

        // RSA-decrypt the per-item encrypted session key
        const encKeyBuf = base64ToArrayBuffer(m.key);
        if (!encKeyBuf || encKeyBuf.byteLength === 0) continue;
        const privateKey = window._rsaKeyPair.privateKey;
        let aesRaw;
        try {
          aesRaw = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encKeyBuf);
        } catch (e) {
          // can't decrypt this item's key; skip
          continue;
        }

        // import AES key and decrypt ciphertext
        const aesKey = await importAesFromRaw(aesRaw);
        if (!aesKey) continue;
        const ctBuf = base64ToArrayBuffer(m.ciphertext);
        const ivBuf = base64ToArrayBuffer(m.iv);
        if (!ctBuf || !ivBuf) continue;

        try {
          const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, aesKey, ctBuf);
          const text = new TextDecoder().decode(plainBuf);
          addMessage({ username: m.sender || m.username || "unknown", message: text, timestamp: m.timestamp });
          continue;
        } catch (e) {
          // decryption failed — fallthrough to plaintext options below
        }
      }

      // fallback: server-stored plaintext or older-format records
      if (m && m.username && m.message) {
        addMessage(m);
      } else if (m && m.sender && m.message) {
        addMessage({ username: m.sender, message: m.message, timestamp: m.timestamp });
      }
    } catch (err) {
      // ignore per-item errors
    }
  }
});

// incoming live message
socket.on("textMessage", async (msg) => {
  try {
    if (msg && msg.encrypted && msg.ciphertext && msg.iv) {
      const sid = msg.sessionId;
      if (!sid || sid !== window._sessionId) {
        socket.emit("request-current-session");
        return;
      }
      if (!window._sessionKey) return;
      const ctBuf = base64ToArrayBuffer(msg.ciphertext);
      const ivBuf = base64ToArrayBuffer(msg.iv);
      if (!ctBuf.byteLength || !ivBuf.byteLength) return;
      try {
        const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, window._sessionKey, ctBuf);
        const text = new TextDecoder().decode(plainBuf);
        addMessage({ username: msg.sender || msg.username || "unknown", message: text, timestamp: msg.timestamp });
      } catch (e) {
        // ignore decryption failure
      }
    } else {
      if (msg && msg.username && msg.message) {
        addMessage(msg);
      } else if (msg && msg.sender && msg.message) {
        addMessage({ username: msg.sender, message: msg.message, timestamp: msg.timestamp });
      }
    }
  } catch (err) {}
});

// join/left UI
socket.on("join", (newuser) => {
  try {
    const newlog = document.createElement("span");
    newlog.classList.add("newlog");
    newlog.innerText = `${newuser || "Unknown"} joined the chat`;
    log.appendChild(newlog);
  } catch (e) {}
});
socket.on("left", (username) => {
  try {
    const newlog = document.createElement("span");
    newlog.classList.add("newlog");
    newlog.innerText = `${username || "Unknown"} left the chat`;
    log.appendChild(newlog);
  } catch (e) {}
});

// RSA keypair generation
async function generateKeyPair() {
  try {
    if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.generateKey) {
      return;
    }
    const kp = await window.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    window._rsaKeyPair = kp;
    const spki = await window.crypto.subtle.exportKey("spki", kp.publicKey);
    const b64 = arrayBufferToBase64(spki);
    window._publicKeyPem = pemFromBase64(b64, "PUBLIC KEY");

    if (socket && socket.connected && window._publicKeyPem) {
      socket.emit("public-key", { publicKeyPem: window._publicKeyPem });
    }
  } catch (e) {
    // ignore
  }
}

// receive session key encrypted to this client
socket.on("session-key", async (data) => {
  try {
    if (!data || !data.encryptedKey) return;
    if (!window._rsaKeyPair || !window.crypto?.subtle?.decrypt) return;

    const encryptedKeyBuffer = base64ToArrayBuffer(data.encryptedKey || "");
    const privateKey = window._rsaKeyPair.privateKey;
    let aesRaw;
    try {
      aesRaw = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedKeyBuffer);
    } catch (e) {
      return;
    }
    const imported = await importAesFromRaw(aesRaw);
    if (imported) {
      window._sessionKey = imported;
      window._sessionId = data.sessionId || null;
      flushMessageQueue();
    }
  } catch (err) {}
});

// encrypt/send
async function encryptAndSendMessage(text) {
  const timestamp = Date.now();
  if (!window._sessionKey || !window._sessionId) {
    outboundQueue.push(text);
    socket.emit("request-current-session");
    return;
  }
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, window._sessionKey, data);
    const ctB64 = arrayBufferToBase64(ct);
    const ivB64 = arrayBufferToBase64(iv.buffer);
    socket.emit("textMessage", {
      encrypted: true,
      sessionId: window._sessionId,
      ciphertext: ctB64,
      iv: ivB64,
      sender: window.USERNAME,
      timestamp,
    });
  } catch (e) {
    outboundQueue.push(text);
    socket.emit("request-current-session");
  }
}

// send UI
if (sendButton && composeBar) {
  sendButton.addEventListener("click", async () => {
    const text = (composeBar.value || "").trim();
    if (!text) return;
    try {
      queueOrSend(text);
    } catch (err) {}
    composeBar.value = "";
  });
  composeBar.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendButton.click();
    }
  });
}

// connection flow
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
  try {
    await generateKeyPair();
  } catch (e) {}
  if (window._publicKeyPem) {
    socket.emit("public-key", { publicKeyPem: window._publicKeyPem });
  }
  socket.emit("join", window.USERNAME);
  socket.emit("request-current-session");
});
