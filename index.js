const express = require("express");
const path = require("path");
const app = express();
const port = 8080;
const { MongoClient } = require("mongodb");
const session = require("express-session");

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
      }
      catch(error)
      {
        console.error("MongoDB connection failed: ",error);
        process.exit(1);
      }  
}

getMongo();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "images"))); 
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));


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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

