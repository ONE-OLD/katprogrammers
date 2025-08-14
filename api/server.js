// /api/server.js
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import {
  initFirebaseAdmin,
  verifySessionCookie,
  createSessionCookie
} from "./utils/auth.js";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json());

// Initialize Firebase Admin
initFirebaseAdmin();
const db = getFirestore();
const adminAuth = getAuth();

// Cookie options
const isProd = process.env.NODE_ENV === "production";
const cookieOpts = {
  httpOnly: true,
  secure: isProd,
  sameSite: "strict",
  path: "/",
  maxAge: 1000 * 60 * 60 * 24 * 5 // 5 days
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

// ---------------- AUTH SESSION ----------------
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

// ---------------- USER INFO ----------------
app.get("/api/me", requireAuth, (req, res) => {
  return res.json({
    uid: req.user.uid,
    email: req.user.email,
    name: req.user.name || null
  });
});

// ---------------- ACTIVITY ----------------
app.post("/api/logActivity", requireAuth, async (req, res) => {
  try {
    const { type, extra } = req.body;
    const ref = db.collection("users").doc(req.user.uid).collection("activity");
    await ref.add({
      type,
      extra: extra || "",
      timestamp: new Date().toISOString()
    });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get("/api/activity", requireAuth, async (req, res) => {
  try {
    const ref = db.collection("users").doc(req.user.uid).collection("activity");
    const snapshot = await ref.orderBy("timestamp", "desc").limit(50).get();
    const activities = snapshot.docs.map(doc => doc.data());
    return res.json(activities);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ---------------- ACCOUNT ACTIONS ----------------
// Change password (requires passing newPassword in body)
app.post("/api/changePassword", requireAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword) {
      return res.status(400).json({ error: "Missing newPassword" });
    }
    await adminAuth.updateUser(req.user.uid, { password: newPassword });
    await logActivity(req.user.uid, "password_changed");
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Delete account
app.delete("/api/deleteAccount", requireAuth, async (req, res) => {
  try {
    await adminAuth.deleteUser(req.user.uid);
    await logActivity(req.user.uid, "account_deleted");
    res.clearCookie("session", { path: "/" });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Helper: Log activity internally
async function logActivity(uid, type, extra = "") {
  const ref = db.collection("users").doc(uid).collection("activity");
  await ref.add({
    type,
    extra,
    timestamp: new Date().toISOString()
  });
}

// ---------------- CACHE CONTROL ----------------
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});

// ---------------- STATIC FILES ----------------
const publicDir = path.join(__dirname, "../public");
const privateDir = path.join(__dirname, "../private-views");

app.use(express.static(publicDir));

app.get("/dashboard", requireAuth, (_req, res) => {
  return res.sendFile(path.join(privateDir, "dashboard.html"));
});

app.get("/profile", requireAuth, (_req, res) => {
  return res.sendFile(path.join(privateDir, "profile.html"));
});

// ---------------- FALLBACK ----------------
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
