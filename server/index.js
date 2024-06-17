// server/index.js
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

app.use(cors({ origin: "http://localhost:3000" }));
app.use(bodyParser.json());

const PORT = process.env.PORT || 5000;
const ENCRYPTION_KEY = "12345678901234567890123456789012"; // 32 bytes key
const IV_LENGTH = 16; // For AES, this is always 16
const SECRET_KEY = "secret_key"; // For JWT
const users = {}; // In-memory user storage. Use a database in production.

function encrypt(buffer) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let encrypted = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
  return encrypted;
}

function decrypt(buffer) {
  let iv = buffer.slice(0, IV_LENGTH);
  let encryptedText = buffer.slice(IV_LENGTH);
  let decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final(),
  ]);
  return decrypted;
}

function ensureUploadsDirectory() {
  const dir = path.join(__dirname, "uploads");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (users[username]) {
    return res.status(400).send("User already exists");
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = { password: hashedPassword };
  res.status(201).send("User registered");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).send("Invalid credentials");
  }
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
  res.json({ token });
});

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (token) {
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return next(new Error("Authentication error"));
      socket.user = user;
      next();
    });
  } else {
    next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  console.log("New client connected");

  socket.on("uploadFile", (data) => {
    ensureUploadsDirectory();
    const filePath = path.join(__dirname, "uploads", data.fileName);
    const encryptedFile = encrypt(Buffer.from(data.file));
    fs.writeFile(filePath, encryptedFile, (err) => {
      if (err) {
        console.error("File upload failed:", err);
        socket.emit("uploadComplete", "Upload failed");
        return;
      }
      console.log("File uploaded:", data.fileName);
      socket.emit("uploadComplete", "Upload successful");
      io.emit("fileUploaded", data.fileName);
    });
  });

  socket.on("downloadFile", (fileName) => {
    const filePath = path.join(__dirname, "uploads", fileName);
    fs.readFile(filePath, (err, file) => {
      if (err) {
        console.error("File download failed:", err);
        socket.emit("fileData", { fileName, file: null });
        return;
      }
      const decryptedFile = decrypt(file);
      socket.emit("fileData", { fileName, file: decryptedFile });
    });
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
