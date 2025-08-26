const express = require("express");
const app = express();
const path = require("path");
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

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "images"))); 
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

//new user connection
io.on('connection',(socket)=>{
  console.log("new user connected");
});

app.get("/", (req, res) => {
  res.render("login"); 
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
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
  res.redirect(`/chat?username=${username}`);
});

app.get("/chat", (req, res) => {
  res.render("chat.ejs");
});

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
