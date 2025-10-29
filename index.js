const express = require("express");
const session = require("express-session");
const app = express();
const path = require("path");
const crypto = require("crypto");
const { randomUUID } = require("crypto");
const { createServer } = require("http");
const server = createServer(app);
const { Server } = require("socket.io");
const io = new Server(server,{
  maxHttpBufferSize: 11534336
});
const port = 8080;
const { MongoClient } = require("mongodb");

const MongoUrl = "mongodb://localhost:3003";
const dbName = "chatApp";
const client = new MongoClient(MongoUrl);

// crypto/session key state
let currentSessionId = null;
let sessions = new Map();      // sessionId -> { key: base64, createdAt }
let publicKeys = new Map();    // socketId -> pubKeyPem

// presence tracking: username -> Set of socketIds
const userSockets = new Map();

let db;

async function getMongo() {
  try {
    await client.connect();
    db = client.db(dbName);
    console.log("Mongo connected");
    // keep dropDatabase only in dev if you want
    await db.dropDatabase();
    console.log("Database cleared");

    server.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  }
}
getMongo();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "images")));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    name: "chat.sid",
    secret: "this_is_secret_hahahaha",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// encrypt the sessionKey (base64) with a client's public PEM using RSA-OAEP+SHA256
function rsaEncryptSessionKeyForClient(pubKeyPem, sessionKeyBase64) {
  const sessionKeyBuf = Buffer.from(sessionKeyBase64, "base64"); // raw bytes
  const encrypted = crypto.publicEncrypt(
    {
      key: pubKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    sessionKeyBuf
  );
  return encrypted.toString("base64");
}

function rotateSessionKey() {
  const newKey = crypto.randomBytes(32).toString("base64");
  const newSessionId = randomUUID();
  currentSessionId = newSessionId;
  sessions.set(newSessionId, { key: newKey, createdAt: Date.now() });

  // send the session key encrypted to every stored public key
  for (const [socketId, pubPem] of publicKeys.entries()) {
    try {
      if (!pubPem) continue;
      const encKeyB64 = rsaEncryptSessionKeyForClient(pubPem, newKey);
      const sock = io.sockets.sockets.get(socketId);
      if (sock) {
        sock.emit("session-key", { sessionId: newSessionId, encryptedKey: encKeyB64, algo: "AES-256-GCM" });
      }
    } catch (err) {
      console.error("Failed to encrypt session key for", socketId, err);
    }
  }
}

io.on("connection", (socket) => {
  console.log("new socket connected:", socket.id);

//   // Debug: log every event this socket receives (temporary)
// socket.onAny((event, ...args) => {
//   try {
//     console.log(`[socket:${socket.id}] event ->`, event, args.length ? args : '(no args)');
//   } catch (e) {
//     console.error('onAny logging error', e);
//   }
// });


  /**
 * Send active usernames (keys of userSockets)
 */
  socket.on("list-users", () => {
    const users = Array.from(userSockets.keys());
    socket.emit("active-users", users);
  });

  // store public key per-socket
  socket.on("public-key", (data) => {
    try {
      if (!data || typeof data.publicKeyPem !== "string") {
        console.warn("Ignoring invalid public-key payload from", socket.id);
        return;
      }
      if (data.publicKeyPem.length > 20000) {
        console.warn("Public key too large from", socket.id);
        return;
      }
      publicKeys.set(socket.id, data.publicKeyPem);

      // If we already have a current session, send it to this socket specifically
      if (currentSessionId && sessions.has(currentSessionId)) {
        try {
          const sessionObj = sessions.get(currentSessionId);
          const encKey = rsaEncryptSessionKeyForClient(data.publicKeyPem, sessionObj.key);
          socket.emit("session-key", { sessionId: currentSessionId, encryptedKey: encKey, algo: "AES-256-GCM" });
        } catch (err) {
          console.error("Immediate session-key send failed to", socket.id, err);
        }
      }
    } catch (err) {
      console.error("Error handling public-key from", socket.id, err);
    }
  });

  socket.on("request-current-session", () => {
    if (!currentSessionId) {
      socket.emit("no-session");
      return;
    }
    const pubPem = publicKeys.get(socket.id);
    if (!pubPem) {
      socket.emit("no-public-key");
      return;
    }
    const sessionObj = sessions.get(currentSessionId);
    if (!sessionObj) {
      socket.emit("no-session");
      return;
    }
    try {
      const encKey = rsaEncryptSessionKeyForClient(pubPem, sessionObj.key);
      socket.emit("session-key", { sessionId: currentSessionId, encryptedKey: encKey, algo: "AES-256-GCM" });
    } catch (err) {
      console.error("Failed to send current session to", socket.id, err);
    }
  });

   socket.on("join", async (username) => {
  // rotate session key on new join (keep your previous behaviour)
  rotateSessionKey();

  try {
    username = (typeof username === "string" ? username.trim() : "");
    if (!username) {
      socket.emit("join-ack", { ok: false, error: "missing_username" });
      return;
    }

    // Ensure this username exists in users collection (user logged in via /login)
    const usersCol = db.collection("users");
    const exists = await usersCol.findOne({ username });
    if (!exists) {
      // If user hasn't performed /login or DB row missing, reject the socket join.
      socket.emit("join-ack", { ok: false, error: "not_logged_in" });
      return;
    }

    // attach username to socket
    socket.username = username;

    // Add this socket id into the presence map
    let set = userSockets.get(username);
    if (!set) {
      set = new Set();
      userSockets.set(username, set);
    }
    set.add(socket.id);

    // Broadcast updated active-users to everyone
    io.emit("active-users", Array.from(userSockets.keys()));


      // gather history from DB and prepare a copy to send (encrypt stored session key per-client)
      const textMessages = db.collection("textMessages");
      const files = db.collection("files");
      const textArray = await textMessages.find({}).toArray();
      const fileArray = await files.find({}).toArray({});
      const history = [...textArray,...fileArray].sort((a,b)=>(a.timestamp)||0-(b.timestamp||0));

      // prepare safe cloned history to send; do NOT mutate DB docs
      const pubPem = publicKeys.get(socket.id);
      const historyToSend = history.map((doc) => {
        const copy = { ...doc };
        // remove internal Mongo-specific _id to avoid any serialization issues
        if (copy._id) delete copy._id;
        // If there is a stored 'key' (the session key base64), encrypt it with client's public key if available
        if (copy.key && pubPem) {
          try {
            copy.key = rsaEncryptSessionKeyForClient(pubPem, copy.key); // now copy.key is encryptedKey base64
          } catch (err) {
            console.error("Failed to encrypt stored session key for history item:", err);
            copy.key = null;
          }
        } else {
          copy.key = null;
        }
        return copy;
      });

      socket.emit("history", historyToSend);
      io.emit("join", username);
      socket.emit("join-ack", { ok: true, username });
    } catch (err) {
      console.error("Error in join handler for socket", socket.id, err);
      socket.emit("join-ack", { ok: false, error: String(err) });
    }
  });

  socket.on("disconnect", async (reason) => {
  try {
    const usernameRaw = socket.username;
    // drop public key for this socket
    publicKeys.delete(socket.id);

    if (!usernameRaw) {
      io.emit("left", "unknown");
      rotateSessionKey();
      return;
    }

    const username = String(usernameRaw).trim();
    if (!username) {
      io.emit("left", "unknown");
      rotateSessionKey();
      return;
    }

    // Remove this socket id from the presence map
    const set = userSockets.get(username);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        // No more live sockets for that username: remove presence and delete DB user (as per your original logic)
        userSockets.delete(username);

        const usersCol = db.collection("users");
        const delRes = await usersCol.deleteOne({ username });
        if (delRes.deletedCount === 0) {
          // fallback: case-insensitive remove if exact match didn't find
          const regex = new RegExp(`^${escapeRegExp(username)}$`, "i");
          await usersCol.deleteOne({ username: { $regex: regex } });
        }
      }
    }

    // broadcast left and active-users update
    io.emit("left", username);
    io.emit("active-users", Array.from(userSockets.keys()));

    // rotate session key because membership changed
    rotateSessionKey();
  } catch (err) {
    console.error("Error in disconnect handler for", socket.id, err);
  }
});
  // handle incoming messages (possibly encrypted)
  socket.on("textMessage", async (msg) => {
    try {
      const textMessages = db.collection("textMessages");

      if (msg && msg.encrypted && msg.ciphertext && msg.iv) {
        const sid = msg.sessionId;
        if (!sid) {
          console.warn("Encrypted message missing sessionId; dropping");
          return;
        }
        const sessionObj = sessions.get(sid);
        if (!sessionObj) {
          console.warn("No session found for sessionId", sid);
          return;
        }
        // broadcast ciphertext as-is
        io.emit("textMessage", msg);
        // store the incoming ciphertext along with the session key (base64) used to encrypt it
        const key = sessionObj.key; // base64
        await textMessages.insertOne({ ...msg, key, storedAt: Date.now() });
      } else {
        await textMessages.insertOne({ ...(msg || {}), timestamp: msg?.timestamp || Date.now() });
        io.emit("textMessage", msg);
      }
    } catch (err) {
      console.error("Error storing/broadcasting message:", err);
    }
  });

  /**
 * Simple file metadata + ciphertext storage (MVP uses in-disk store)
 * Expectation from client: { encrypted: true, sessionId?, ciphertext: base64, iv: base64, filenameEncrypted?, mime, size, sender, timestamp }
 */
socket.on("file-meta", async (meta) => {
  try {
    const filesCol = db.collection("files");
    // sanitize and store meta as-is (server never decrypts)
    const sid = meta.sessionId
    const sessionOBJ = sessions.get(sid)
    const key = sessionOBJ.key
    const rec = {
      ...meta,
      key,
      storedAt: Date.now()
    };
    await filesCol.insertOne(rec);
      // broadcast to all
      io.emit("file-meta", rec);
  } catch (err) {
  }
  });

  /** helper: relay to all sockets for a username */
function relayToUser(targetUsername, eventName, payload) {
  const set = userSockets.get(targetUsername);
  if (!set) return;
  for (const sid of set) {
    const sock = io.sockets.sockets.get(sid);
    if (sock) sock.emit(eventName, payload);
  }
}

/** Offer */
socket.on("webrtc-offer", (data) => {
  const to = data?.to;
  if (!to) return;
  const payload = { from: socket.username };
  if (data.offer) payload.offer = data.offer;
  if (typeof data.media !== "undefined") payload.media = !!data.media;
  if (data.candidate) payload.candidate = data.candidate;
  relayToUser(to, "webrtc-offer", payload);
});

/** Answer */
socket.on("webrtc-answer", (data) => {
  const to = data?.to;
  if (!to) return;
  const payload = { from: socket.username };
  if (data.answer) payload.answer = data.answer;
  if (typeof data.media !== "undefined") payload.media = !!data.media;
  if (data.candidate) payload.candidate = data.candidate;
  relayToUser(to, "webrtc-answer", payload);
});

/** ICE candidate */
socket.on("webrtc-ice", (data) => {
  const to = data?.to;
  if (!to || !data.candidate) return;
  const payload = { from: socket.username, candidate: data.candidate };
  if (typeof data.media !== "undefined") payload.media = !!data.media;
  relayToUser(to, "webrtc-ice", payload);
});

socket.on("webrtc-hangup", (data) => {
  const to = data?.to;
  if (!to) return;
  relayToUser(to, "webrtc-hangup", { from: socket.username });
});

/** Optional: a lightweight "call-request" so UI can show incoming call popup */
socket.on("private-call-request", (data) => {
  const { to, callType } = data || {};
  if (!to) return;
  relayToUser(to, "private-call-request", { from: socket.username, callType });
});
});
// Express routes (unchanged)
app.get("/", (req, res) => {
  const { error } = req.query;
  res.render("login", { error });
});

app.post("/login", async (req, res) => {
  const username = (req.body.username || "").trim();
  if (!username) {
    return res.redirect("/?error=missing_username");
  }
  const users = db.collection("users");
  const exists = await users.findOne({ username });
  if (!exists) {
    await users.insertOne({ username });
    req.session.username = username;
    return res.redirect(`/chat?username=${encodeURIComponent(username)}`);
  } else {
    return res.redirect("/?error=username_taken");
  }
});

app.get("/chat", async (req, res) => {
  const username = (req.query.username || "").trim();
  const sessionUser = req.session.username;

  if (!sessionUser || sessionUser !== username) {
    return res.redirect("/");
  }

  const users = db.collection("users");
  const exists = await users.findOne({ username });
  if (!exists) {
    return res.redirect("/");
  }

  res.render("chat", { username });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    return res.redirect("/");
  });
});
