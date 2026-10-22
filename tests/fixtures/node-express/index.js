// Deliberately vulnerable fixture. Never deploy.
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/health", (req, res) => res.send("ok"));
app.get("/run", (req, res) => exec("ls " + req.query.dir, (e, out) => res.send(out)));
app.get("/hello", (req, res) => res.send("<h1>Hello " + req.query.name + "</h1>"));
app.listen(3000);
