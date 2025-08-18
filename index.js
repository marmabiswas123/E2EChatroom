const express = require("express");
const path = require("path");
const app = express();
const port = 8080;


app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "images"))); 
app.use(express.static(path.join(__dirname, "public")));


app.use(express.urlencoded({ extended: true }));


app.get("/", (req, res) => {
  res.render("login"); 
});

app.post("/login", (req, res) => {

  res.redirect("/chat");
});

app.get("/chat", (req, res) => {
  res.render("chat.ejs");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

