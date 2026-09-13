const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");

const app = express();
const MemoryStore = require("memorystore")(session);
const { review } = require("../bot/bot");

const PORT = Number(process.env.PORT || 3000);
const FLAG = process.env.FLAG || "pwnsec{real_flag_on_remote}";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const BOT_TOKEN = process.env.BOT_TOKEN || "dev-token";

const notes = new Map();
let currentReview = null;

function randomId(bytes = 8) {
  return crypto.randomBytes(bytes).toString("hex");
}

function requireBot(req, res, next) {
  if (req.get("x-bot-token") !== BOT_TOKEN) {
    res.status(403).type("text/plain").send("forbidden");
    return;
  }
  next();
}

function policy(req) {
  return Object.entries({
    "sec-fetch-site": "none",
    "sec-fetch-dest": "document",
  })
    .every(([header, expected]) => req.get(header) === expected);
}

function consumeReport(req) {
  const id = String(req.query.rid || "");
  const state = String(req.query.state || "");

  if (
    !currentReview
    || currentReview.id !== id
    || state !== currentReview.nonce
    || !currentReview.prepared
    || !currentReview.approved
    || currentReview.used
  ) {
    return false;
  }

  currentReview.used = true;
  return true;
}

function reviewMatches(req) {
  return currentReview && currentReview.id === String(req.query.rid || "");
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  store: new MemoryStore({ checkPeriod: 60 * 60 * 1000 }),
  name: "sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
  },
}));
app.use(express.static(path.join(__dirname, "../public")));

app.get("/", (req, res) => {
  const visibleNotes = [...notes.values()]
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, 5);

  res.render("index", { title: "Dashboard", notes: visibleNotes });
});

app.post("/create", (req, res) => {
  const title = String(req.body.title || "").trim().slice(0, 10);
  const html = String(req.body.html || "").slice(0, 128);

  if (!title || !html) {
    res.status(400).render("message", { title: "Bad note", message: "Missing title or body." });
    return;
  }

  const id = randomId(10);
  notes.set(id, {
    id,
    title,
    html,
    createdAt: Date.now(),
  });

  res.redirect(`/note/${encodeURIComponent(id)}`);
});

app.get("/note/:id", (req, res) => {
  const note = notes.get(req.params.id);
  if (!note) {
    res.status(404).render("message", { title: "Missing", message: "Document not found." });
    return;
  }

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.render("note", { title: note.title, note });
});

app.get("/review", (req, res) => {
  if (!reviewMatches(req)) {
    res.status(404).type("text/plain").send("not found");
    return;
  }

  let target;
  try {
    target = new URL(String(req.query.u || ""));
  } catch {
    res.status(400).type("text/plain").send("bad url");
    return;
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    res.status(400).type("text/plain").send("bad url");
    return;
  }

  target.searchParams.set("rid", currentReview.id);
  currentReview.document = {
    url: target.href,
    nonce: randomId(16),
  };
  
  const nonce = randomId(16);
  const origin = `${req.protocol}://${req.get("host")}`;
  res.setHeader("Content-Security-Policy", [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'self'",
    `frame-src ${origin}/sandbox`,
    "connect-src 'self'",
    "frame-ancestors 'none'",
  ].join("; "));
  res.render("review", {
    nonce,
    id: currentReview.id,
    state: currentReview.nonce,
  });
});

app.get("/sandbox", (req, res) => {
  if (!reviewMatches(req) || !currentReview.document) {
    res.status(404).type("text/plain").send("not found");
    return;
  }

  const { url, nonce } = currentReview.document;
  res.setHeader("Content-Security-Policy", [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ].join("; "));
  if (req.query.end !== undefined) {
    res.type("html").send("<!doctype html>");
    return;
  }

  res.render("sandbox", { nonce, url });
});

app.post("/complete", (req, res) => {
  const id = String(req.body.id || "");
  const state = String(req.body.state || "");

  if (currentReview && currentReview.id === id && currentReview.prepared && req.session.admin && state === currentReview.nonce) {
    currentReview.approved = true;
  }

  res.type("text/plain").send("ok");
});

app.get("/api/flag", (req, res) => {
  if (!req.session.admin || !currentReview) {
    res.status(403).json({ error: "reviewer only" });
    return;
  }

  if (!currentReview.flag) {
    currentReview.flag = FLAG;
  }

  res.json({ flag: currentReview.flag });
});

app.post("/report", async (req, res) => {
  if (currentReview) {
    res.status(429).render("message", { title: "Reviewer busy", message: "The reviewer is already checking a document. Try again shortly." });
    return;
  }

  let target;
  try {
    target = new URL(String(req.body.url || ""));
  } catch {
    res.status(400).render("message", { title: "Invalid URL", message: "Invalid URL." });
    return;
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    res.status(400).render("message", { title: "Invalid URL", message: "Only HTTP and HTTPS URLs are accepted." });
    return;
  }

  const noteId = String(target.searchParams.get("note") || "");
  const id = randomId(12);
  currentReview = {
    id,
    url: target.href,
    noteId,
    prepared: false,
    approved: false,
    used: false,
    visited: false,
    nonce: randomId(16),
    flag: null,
  };

  try {
    await review(currentReview);
    res.render("message", { title: "Reviewed", message: "The reviewer finished." });
  } catch (error) {
    res.status(500).render("message", { title: "Review failed", message: "The reviewer could not open that URL." });
  } finally {
    currentReview = null;
  }
});

app.get("/reports/session", (req, res) => {
  if (req.get("x-bot-token") === BOT_TOKEN) {
    req.session.name = "reviewer";
    req.session.admin = true;
  }

  if (!req.session.admin) {
    res.status(403).type("text/plain").send("forbidden");
    return;
  }

  res.type("text/plain").send("ok");
});

app.get("/reports/check", (req, res) => {
  res.setHeader("Vary", "Cookie");

  if (!req.session.admin) {
    res.status(403).type("text/plain").send("forbidden");
    return;
  }

  const id = String(req.query.rid || "");
  if (!currentReview || currentReview.id !== id) {
    res.status(404).type("text/plain").send("not found");
    return;
  }

  if (currentReview.visited) {
    const note = notes.get(currentReview.noteId);
    if (!note) {
      res.status(404).type("text/plain").send("not found");
      return;
    }

    if (!policy(req) || !consumeReport(req)) {
      res.status(403).type("text/plain").send("forbidden");
      return;
    }

    res.render("review-document", { note });
    return;
  }

  currentReview.visited = true;
  res.cookie("view", id, {
    httpOnly: true,
    sameSite: "lax",
    path: "/reports/check",
  });
  res.type("html").send("<!doctype html><title>Reviewer</title><p>Opening document.</p>");
});

app.post("/reports/arm/:id", requireBot, (req, res) => {
  if (!currentReview || currentReview.id !== req.params.id || currentReview.used) {
    res.status(404).type("text/plain").send("not found");
    return;
  }

  currentReview.prepared = true;
  res.type("text/plain").send("ok");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[readonce] listening on 0.0.0.0:${PORT}`);
});
