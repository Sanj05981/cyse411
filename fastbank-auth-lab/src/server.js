const express = require("express");
const parser = require("body-parser");
const cookies = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;


app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'"
    ].join("; ")
  );

  res.setHeader(
    "Permissions-Policy",
    [
      "camera=()",
      "microphone=()",
      "geolocation=()",
      "fullscreen=(self)"
    ].join(", ")
  );

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  res.setHeader("X-Content-Type-Options", "nosniff");

  next();
});


app.use(parser.json());
app.use(parser.urlencoded({ extended: false }));
app.use(cookies());
app.use(express.static("public"));


const ROUNDS = 10;
const rawPassword = "password123";
const hashedPassword = bcrypt.hashSync(rawPassword, ROUNDS);

const ACCOUNTS = [
  {
    id: 1,
    username: "student",
    secret: hashedPassword
  }
];

const ACTIVE_SESSIONS = {}; // token → { userId, expires }


function resolveSession(req) {
  const token = req.cookies.session;
  if (!token || !ACTIVE_SESSIONS[token]) return null;

  const record = ACTIVE_SESSIONS[token];

  if (Date.now() > record.expires) {
    delete ACTIVE_SESSIONS[token];
    return null;
  }

  return record;
}


app.get("/api/me", (req, res) => {
  const session = resolveSession(req);

  if (!session) {
    return res.status(401).json({ authenticated: false });
  }

  const user = ACCOUNTS.find((u) => u.id === session.userId);
  return res.json({
    authenticated: true,
    username: user.username
  });
});

// --------------------------
// POST: Login
// --------------------------
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const genericResponse = {
    success: false,
    message: "Invalid username or password"
  };

  const account = ACCOUNTS.find((u) => u.username === username);
  if (!account) {
    return res.status(401).json(genericResponse);
  }

  const verified = await bcrypt.compare(password, account.secret);
  if (!verified) {
    return res.status(401).json(genericResponse);
  }

  const token = crypto.randomUUID();
  ACTIVE_SESSIONS[token] = {
    userId: account.id,
    expires: Date.now() + 60 * 60 * 1000
  };

  res.cookie("session", token, {
    httpOnly: true,
    secure: false, // set to true for HTTPS environments
    sameSite: "strict",
    maxAge: 60 * 60 * 1000
  });

  return res.json({ success: true, token });
});

// --------------------------
// POST: Logout
// --------------------------
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;

  if (token && ACTIVE_SESSIONS[token]) {
    delete ACTIVE_SESSIONS[token];
  }

  res.clearCookie("session");
  return res.json({ success: true });
});

// --------------------------
// Default Route
// --------------------------
app.use((req, res) => {
  res.status(404).send("Not found");
});

// --------------------------
// Server Startup
// --------------------------
app.listen(PORT, () => {
  console.log(`Auth service online at http://localhost:${PORT}`);
});
