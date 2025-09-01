const express = require("express");
const app = express();
const path = require("path");
const fs = require("fs");
const {createServer}=require("http");
const server = createServer(app);
const {Server} = require("socket.io");
const io = new Server(server);
const port = 8080;
const { MongoClient } = require("mongodb");


//MongoDB connection setup
const MongoUrl = "mongodb://localhost:3003";
const dbName = "chatApp";
const client = new MongoClient(MongoUrl);

//connecting to mongodb
let db;
async function getMongo() {
      try
      {
        await client.connect();
        console.log("MongoDB connection successful");
        db = client.db(dbName);
        await clearDatabase();
      }
      catch(error)
      {
        console.error("MongoDB connection failed: ",error);
        process.exit(1);
      }  
}

async function clearDatabase() {
  try {
    await db.dropDatabase();
    console.log("Database cleared at startup");
  } catch (err) {
    console.error("Failed to clear database:", err);
  }
}
getMongo();

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "images"))); 
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

//new user connection
io.on('connection',(socket)=>{
  console.log("new user connected");
  socket.on("join",async (username)=>{
    socket.username = username;
  });
  //socket on text messages
  socket.on("textMessage",async (msg)=>{
    const textMessages = db.collection("textMessages");
    await textMessages.insertOne(msg);
    io.emit("textMessage",(msg));
  });
   socket.on("attachment", async (file) => {
    //debug
    const debug = {
      type: "text",
      username: "Alien",
      message: "Debug message",
      timestamp: Date.now(),
    }
    io.emit("textMessage",debug);
    try {
      const attachments = db.collection("attachments");

      // Save locally for caching
      const fileBuffer = Buffer.from(new Uint8Array(file.data));
      const localPath = path.join(UPLOAD_DIR, file.fileName);
      if (!fs.existsSync(localPath)) {
        fs.writeFileSync(localPath, fileBuffer);
      }

      // Store in DB
      const insertResult = await attachments.insertOne(file);
      const maintype = file.mimeType.split("/")[0];
      if(maintype == "image"){
        io.emit("image",localPath);
      }

      // Generate URL
      const fileUrl = `/file?name=${encodeURIComponent(file.fileName)}`;

      // Emit metadata
      io.emit("attachment", {
        _id: insertResult.insertedId,
        username: file.username,
        fileName: file.fileName,
        mimeType: file.mimeType,
        url: fileUrl,
        timestamp: file.timestamp,
        type: "attachment",
      });
    } catch (err) {
      console.error("Attachment save error:", err);
    }
  });
});

app.get("/file", async (req, res) => {
  const fileName = req.query.name;
  if (!fileName) return res.status(400).send("File name required");

  const localPath = path.join(UPLOAD_DIR, fileName);

  if (fs.existsSync(localPath)) {
    return res.download(localPath, fileName); // serve cached file
  }

  // Fetch from DB if not cached
  const attachments = db.collection("attachments");
  const fileDoc = await attachments.findOne({ fileName });
  if (!fileDoc) return res.status(404).send("File not found");

  // Save locally for future requests
  fs.writeFileSync(localPath, Buffer.from(fileDoc.data));

  return res.download(localPath, fileName);
});

app.get("/", (req, res) => {
  res.render("login"); 
});

app.post("/login", async (req, res) => {
  const username = (req.body.username||"").trim();
  if(!username){
    return res.redirect("/");
    //error reflection required! 
  }
  const users = db.collection("users");
  const exists = await users.findOne({username});
  if(!exists){
    await users.insertOne({username});
  }
  else{
    res.redirect("/");
  }
  return res.redirect(`/chat?username=${encodeURIComponent(username)}`);
});

app.get("/chat", (req, res) => {
  const username = req.query.username;
  if(!username){
    return res.redirect("/");
  }
  res.render("chat.ejs", { username });
});

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
