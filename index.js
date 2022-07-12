const mysql = require("mysql2");
const dotenv = require("dotenv").config({ path: "./vars/.env" });
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcryptjs");
const hbs = require("hbs");
const { connection } = require("./config/db.config");

const PORT = process.env.PORT;

const app = express();

const corsOption = {
  origin: "localhost:3000",
};

// PARSERS
// app.use(cors(corsOption));
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

// HANDLEBARS
app.set("view engine", "hbs");
hbs.registerPartials(path.join(__dirname + "/views/partials"));

// GET

// get_default
app.get("/", (req, res) => {
  connection.connect(() => {
    console.log("Connected!");
  });
  res.render("login");
});

// get_users
app.get("/users", (req, res) => {
  let sql = "SELECT id, username, email FROM accounts";
  connection.query(sql, (error, results, fields) => {
    if (error) throw error;
    res.send(results);
  });
});

// get_register
app.get("/register", (req, res) => {
  res.render("register");
});

// get_home
app.get("/home", (req, res) => {
  req.session.loggedin
    ? res.send("Welcome back, " + req.session.username + "!")
    : res.send("Please login to view this page!");
  res.end();
});

// POST

// post_auth
app.post("/auth", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username && password) {
    connection.query(
      "SELECT * FROM accounts WHERE username = ?",
      [username],
      async (error, results, fields) => {
        if (error) throw error;

        const comparison = await bcrypt.compare(password, results[0].password);

        if (results.length > 0 && comparison) {
          req.session.loggedin = true;
          req.session.username = username;
          res.redirect("/home");
        } else {
          res.render("login", {
            error: "Incorrect Username and/or Password!",
          });
          return;
        }
        res.end();
      }
    );
  } else {
    res.send("Please enter Username and Password!");
    res.end();
  }
});

// post_register
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  const saltRounds = 10;
  const encryptedPassword = await bcrypt.hash(password, saltRounds);

  if (username && password && email) {
    connection.query(
      "SELECT username FROM accounts",
      (error, results, fields) => {
        if (error) throw error;

        const user = results.find((user) => username === user.username);

        if (user) {
          res.render("register", {
            error: "Username already registered, try another one",
          });
          return;
        } else {
          connection.query(
            "INSERT INTO accounts (username, password, email) VALUES(?,?,?)",
            [username, encryptedPassword, email],
            (error, results, fields) => {
              if (error) throw error;

              res.render("login", {
                success: "You have successfully created your account",
              });
              return;
            }
          );
        }
      }
    );
  } else {
    res.send("Please enter Username, Password and Email!");
    res.end();
  }
});

// LISTEN
app.listen(PORT, () => {
  console.log(`Server on ${PORT}`);
});
