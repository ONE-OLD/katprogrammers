// /api/server.js
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { initFirebaseAdmin, verifySessionCookie, createSessionCookie } from "./utils/auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json());

// Initialize Firebase Admin
initFirebaseAdmin();

// Directories
const publicDir = path.join(__dirname, "../public");
const privateDir = path.join(__dirname, "../private-views");

// Cookie options
const isProd = process.env.NODE_ENV === "production";
const cookieOpts = {
  httpOnly: true,
  secure: isProd,
  sameSite: "strict",
  path: "/"
};

// Auth middleware
async function requireAuth(req, res, next) {
  const sessionCookie = req.cookies.session || null;
  if (!sessionCookie) return res.redirect("/login.html");

  try {
    const decoded = await verifySessionCookie(sessionCookie);
    req.user = decoded;
    return next();
  } catch {
    return res.redirect("/login.html");
  }
}

// API endpoints
app.post("/sessionLogin", async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ error: "Missing idToken" });

  try {
    const sessionCookie = await createSessionCookie(idToken);
    res.cookie("session", sessionCookie, cookieOpts);
    return res.json({ ok: true });
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/sessionLogout", (_req, res) => {
  res.clearCookie("session", { path: "/" });
  return res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  return res.json({ uid: req.user.uid, email: req.user.email, name: req.user.name || null });
});

// Serve static public files
app.use(express.static(publicDir));

// Protected pages
app.get("/dashboard", requireAuth, (_req, res) => {
  return res.sendFile(path.join(privateDir, "dashboard.html"));
});

// SPA fallback
app.get("*", (req, res) => {
  const potentialFile = path.join(publicDir, req.path);
  if (potentialFile.startsWith(publicDir)) {
    try {
      return res.sendFile(potentialFile);
    } catch {}
  }
  return res.sendFile(path.join(publicDir, "index.html"));
});

export default app;
