const mysql = require("mysql2");
const dotenv = require("dotenv").config({ path: "./vars/.env" });
const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcryptjs");
const hbs = require("hbs");

const PORT = process.env.PORT;

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

const app = express();

// PARSERS
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

connection.connect((err) => {
  if (err) throw err;
  console.log("Connected!");
  let username = "test";
  let sql = "SELECT * FROM accounts WHERE username = ?";
  connection.query(sql, [username], (err, result) => {
    if (err) throw err;
    console.log(result);
  });
});

// GET
app.get("/", (req, res) => {
  res.render("login");
});
// get_register
app.get("/register", (req, res) => {
  res.render("register");
});
// get_home
app.get("/home", (request, res) => {
  request.session.loggedin
    ? res.send("Welcome back, " + request.session.username + "!")
    : res.send("Please login to view this page!");
  res.end();
});

// POST
app.post("/auth", (request, res) => {
  const username = request.body.username;
  const password = request.body.password;

  if (username && password) {
    connection.query(
      "SELECT * FROM accounts WHERE username = ?",
      [username],
      async (error, results, fields) => {
        if (error) throw error;

        const comparison = await bcrypt.compare(password, results[0].password);

        if (results.length > 0 && comparison) {
          request.session.loggedin = true;
          request.session.username = username;
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

app.post("/register", async (request, res) => {
  const username = request.body.registerUsername;
  const password = request.body.registerPassword;
  const email = request.body.registerEmail;

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

              res.redirect("/");

              res.end();
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

app.listen(PORT, () => {
  console.log(`Server on ${PORT}`);
});
