const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");

const SECRET = process.env.JWT_SECRET || "supersecret";
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());
app.use("/uploads", express.static("uploads"));

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const io = new Server(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST"]
  }
});

// ================= DATABASE =================

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE,
    password TEXT,
    nickname TEXT,
    avatar TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromUser INTEGER,
    toUser INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1 INTEGER,
    user2 INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender INTEGER,
    receiver INTEGER,
    text TEXT,
    file TEXT,
    type TEXT,
    time TEXT
  )`);
});

// ================= AUTH =================

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// ================= FILE UPLOAD =================

const storage = multer.diskStorage({
  destination: "uploads",
  filename: (_, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// ================= SOCKET =================

let onlineUsers = {};

io.on("connection", socket => {

  socket.on("online", userId => {
    onlineUsers[userId] = socket.id;
    io.emit("online-users", Object.keys(onlineUsers));
  });

  socket.on("send-message", data => {
    db.run(
      `INSERT INTO messages (sender, receiver, text, file, type, time)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        data.sender,
        data.receiver,
        data.text,
        data.file,
        data.type,
        new Date().toISOString()
      ]
    );

    if (onlineUsers[data.receiver]) {
      io.to(onlineUsers[data.receiver]).emit("receive-message", data);
    }
  });

  socket.on("disconnect", () => {
    for (let id in onlineUsers) {
      if (onlineUsers[id] === socket.id) delete onlineUsers[id];
    }
    io.emit("online-users", Object.keys(onlineUsers));
  });

});

// ================= AUTH ROUTES =================

app.post("/api/register", async (req, res) => {
  const { login, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (login, password, nickname) VALUES (?, ?, ?)",
    [login, hash, login],
    err => {
      if (err) return res.status(400).json({ error: "Login exists" });
      res.json({ success: true });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { login, password } = req.body;

  db.get("SELECT * FROM users WHERE login=?", [login], async (err, user) => {
    if (!user) return res.status(400).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token, user });
  });
});

// ================= CHANGE NICKNAME =================

app.post("/api/change-nickname", auth, (req, res) => {
  const { nickname } = req.body;

  if (!nickname || nickname.length < 2)
    return res.status(400).json({ error: "Ник слишком короткий" });

  db.run(
    "UPDATE users SET nickname=? WHERE id=?",
    [nickname, req.user.id],
    err => {
      if (err) return res.status(500).json({ error: "Ошибка базы" });
      res.json({ success: true });
    }
  );
});

// ================= AVATAR =================

app.post("/api/upload-avatar", auth, upload.single("avatar"), (req, res) => {
  const url = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;

  db.run("UPDATE users SET avatar=? WHERE id=?", [
    url,
    req.user.id
  ]);

  res.json({ url });
});

// ================= FILE UPLOAD =================

app.post("/api/upload", auth, upload.single("file"), (req, res) => {
  const url = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
  res.json({ url });
});

// ================= MESSAGES =================

app.get("/api/messages/:id", auth, (req, res) => {
  db.all(
    `SELECT * FROM messages
     WHERE (sender=? AND receiver=?)
     OR (sender=? AND receiver=?)
     ORDER BY id ASC`,
    [req.user.id, req.params.id, req.params.id, req.user.id],
    (err, rows) => res.json(rows)
  );
});

// ================= FRIEND REQUESTS =================

app.post("/api/send-request", auth, (req, res) => {
  const { login } = req.body;

  db.get("SELECT id FROM users WHERE login=?", [login], (err, user) => {
    if (!user) return res.status(404).json({ error: "User not found" });

    db.run(
      "INSERT INTO friend_requests (fromUser, toUser) VALUES (?, ?)",
      [req.user.id, user.id]
    );

    res.json({ success: true });
  });
});

app.get("/api/requests", auth, (req, res) => {
  db.all(
    `SELECT users.id, users.nickname, users.login, users.avatar
     FROM friend_requests
     JOIN users ON friend_requests.fromUser = users.id
     WHERE friend_requests.toUser=?`,
    [req.user.id],
    (err, rows) => res.json(rows)
  );
});

app.post("/api/accept-request", auth, (req, res) => {
  const { fromId } = req.body;

  db.run("INSERT INTO friends (user1, user2) VALUES (?,?)", [
    req.user.id,
    fromId
  ]);

  db.run(
    "DELETE FROM friend_requests WHERE fromUser=? AND toUser=?",
    [fromId, req.user.id]
  );

  res.json({ success: true });
});

// ================= FRIENDS =================

app.get("/api/friends", auth, (req, res) => {
  db.all(
    `SELECT users.id, users.nickname, users.login, users.avatar
     FROM friends
     JOIN users ON users.id = friends.user2
     WHERE friends.user1=?
     UNION
     SELECT users.id, users.nickname, users.login, users.avatar
     FROM friends
     JOIN users ON users.id = friends.user1
     WHERE friends.user2=?`,
    [req.user.id, req.user.id],
    (err, rows) => res.json(rows)
  );
});

// ================= REMOVE FRIEND =================

app.post("/api/remove-friend", auth, (req, res) => {
  const { friendId } = req.body;

  db.run(
    `DELETE FROM friends
     WHERE (user1=? AND user2=?)
     OR (user1=? AND user2=?)`,
    [req.user.id, friendId, friendId, req.user.id]
  );

  res.json({ success: true });
});

// ================= START =================

server.listen(PORT, () =>
  console.log("🔥 Server running on port " + PORT)
);