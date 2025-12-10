// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();


const BASE_DIR = path.join(__dirname, "files");

(function ensureBaseDir() {
  try {
    fs.mkdirSync(BASE_DIR, { recursive: true });
  } catch (_) {
    
  }
})();


app.use((req, res, next) => {
  res.removeHeader("X-Powered-By");

  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'"
  ].join("; ");

  res.setHeader("Content-Security-Policy", csp);
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), fullscreen=(self)"
  );

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));


function resolveSafe(baseDir, userInput) {
  let decoded = userInput;

  try {
    decoded = decodeURIComponent(userInput);
  } catch (_) {
    
  }

  const candidate = path.resolve(baseDir, decoded);

  const baseNormalized =
    baseDir.endsWith(path.sep) ? baseDir : baseDir + path.sep;

  if (!candidate.startsWith(baseNormalized)) {
    return null;
  }

  return candidate;
}


app.post(
  "/read",
  [
    body("filename")
      .exists()
      .withMessage("filename required")
      .bail()
      .isString()
      .withMessage("filename must be a string")
      .bail()
      .trim()
      .notEmpty()
      .withMessage("filename must not be empty")
      .bail()
      .custom((val) => {
        if (val.includes("\0")) throw new Error("null byte not allowed");
        return true;
      })
  ],
  (req, res) => {
    const issues = validationResult(req);
    if (!issues.isEmpty()) {
      return res.status(400).json({ errors: issues.array() });
    }

    const { filename } = req.body;
    const safePath = resolveSafe(BASE_DIR, filename);

    if (!safePath) {
      return res.status(403).json({ error: "Path traversal detected" });
    }

    try {
      const data = fs.readFileSync(safePath, "utf8");
      return res.json({ path: safePath, content: data });
    } catch (err) {
      if (err.code === "ENOENT") {
        return res.status(404).json({ error: "File not found" });
      }
      if (err.code === "EISDIR") {
        return res.status(400).json({ error: "Cannot read a directory" });
      }
      console.error(err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
);


app.post("/read-no-validate", (req, res) => {
  const filename = req.body.filename || "";
  const joined = path.join(BASE_DIR, filename);

  if (!fs.existsSync(joined)) {
    return res.status(404).json({ error: "File not found", path: joined });
    }

  try {
    const contents = fs.readFileSync(joined, "utf8");
    return res.json({ path: joined, content: contents });
  } catch (_) {
    return res.status(500).json({ error: "Read error" });
  }
});


app.post("/setup-sample", (req, res) => {
  const templates = {
    "hello.txt": "Hello from safe rewritten file!\n",
    "notes/readme.md": "# Readme\nSample content here."
  };

  try {
    for (const [relative, text] of Object.entries(templates)) {
      const resolved = resolveSafe(BASE_DIR, relative);
      if (!resolved) continue;

      const dir = path.dirname(resolved);
      fs.mkdirSync(dir, { recursive: true });

      fs.writeFileSync(resolved, text, "utf8");
    }

    return res.json({ ok: true, base: BASE_DIR });
  } catch (err) {
    return res.status(500).json({ error: "Setup failed" });
  }
});


app.use((req, res) => {
  res.status(404).send("Not found");
});


if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}

module.exports = app;
