require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const { ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const dns = require("node:dns/promises");

dns.setServers(["1.1.1.1", "8.8.8.8"]);
const app = express();
const Joi = require("joi");

app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

let mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
    cookie: { maxAge: expireTime },
  }),
);

app.get("/", (req, res) => {
  if (req.session && req.session.authenticated) {
    res.render("index", {
      loginStatus: true,
      name: req.session.name,
      active: "home",
      title: "Home",
    });
  } else {
    res.render("index", { loginStatus: false, active: "home", title: "Home" });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup", { active: "signup", title: "Sign Up" });
});

app.get("/login", (req, res) => {
  res.render("login", { active: "login", title: "Login" });
});

app.post("/loginSubmit", async (req, res) => {
  let email = req.body.email;
  let password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().max(50).required(),
    password: Joi.string().min(5).max(100).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error) {
    res.render("errorMessage", {
      active: "none",
      errorId: 0,
      errorMsg: validationResult.error.message,
      title: "Error",
    });
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1, user_type: 1 })
    .toArray();
  if (result.length != 1) {
    res.render("errorMessage", { active: "none", errorId: 1, title: "Error" });
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    res.render("errorMessage", { active: "none", errorId: 2, title: "Error" });
    return;
  }
});

app.post("/signupSubmit", async (req, res) => {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().max(50).required(),
    password: Joi.string().min(5).max(100).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error) {
    res.render("errorMessage", {
      active: "none",
      errorId: 3,
      errorMsg: validationResult.error.message,
      title: "Error",
    });
    return;
  }
  const existingUser = await userCollection.findOne({ email: email });

  if (existingUser) {
    res.render("errorMessage", { active: "none", errorId: 4, title: "Error" });
    return;
  }

  let hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });
  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (req.session && req.session.authenticated) {
    res.render("members", {
      name: req.session.name,
      active: "members",
      title: "Members",
    });
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/admin", async (req, res) => {
  if (
    req.session &&
    req.session.authenticated &&
    req.session.user_type === "admin"
  ) {
    const result = await userCollection
      .find()
      .project({ name: 1, _id: 1 })
      .toArray();
    res.render("admin", { active: "admin", title: "Admin", users: result });
  } else if (
    req.session &&
    req.session.authenticated &&
    req.session.user_type === "user"
  ) {
    res.render("errorMessage", { active: "none", title: "Error", errorId: 5 });
  } else {
    res.redirect("/");
  }
});

app.post("/promote/:id", async (req, res) => {
  const userId = req.params.id;

  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "admin" } },
  );

  res.redirect("/admin");
});

app.post("/demote/:id", async (req, res) => {
  const userId = req.params.id;

  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "user" } },
  );

  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.render("404", { title: 404, active: "none" });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
