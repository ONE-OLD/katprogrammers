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

/* ---------------- MIDDLEWARE (ORDER FIXED) ---------------- */
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());

// Cache control (must be before routes)
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});

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
  maxAge: 1000 * 60 * 60 * 24 * 5
};

/* ---------------- AUTH MIDDLEWARE ---------------- */
async function requireAuth(req, res, next) {
  const sessionCookie = req.cookies.session || null;

  if (!sessionCookie) {
    if (req.path.startsWith("/api")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return res.redirect("/login");
  }

  try {
    const decoded = await verifySessionCookie(sessionCookie);
    req.user = decoded;
    next();
  } catch {
    if (req.path.startsWith("/api")) {
      return res.status(401).json({ error: "Invalid session" });
    }
    return res.redirect("/login");
  }
}

/* ---------------- AUTH SESSION ---------------- */
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

app.post("/sessionLogout", async (req, res) => {
  const sessionCookie = req.cookies.session || null;

  res.clearCookie("session", cookieOpts);

  if (sessionCookie) {
    try {
      const decoded = await adminAuth.verifySessionCookie(sessionCookie, true);
      await adminAuth.revokeRefreshTokens(decoded.sub);
    } catch {
      // already invalid
    }
  }

  return res.json({ ok: true });
});

/* ---------------- USER INFO ---------------- */
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    uid: req.user.uid,
    email: req.user.email,
    name: req.user.name || null
  });
});

/* ---------------- ACTIVITY ---------------- */
app.post("/api/logActivity", requireAuth, async (req, res) => {
  try {
    const { type, extra } = req.body;
    const ref = db.collection("users").doc(req.user.uid).collection("activity");
    await ref.add({
      type,
      extra: extra || "",
      timestamp: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/activity", requireAuth, async (req, res) => {
  try {
    const ref = db.collection("users").doc(req.user.uid).collection("activity");
    const snapshot = await ref.orderBy("timestamp", "desc").limit(50).get();
    res.json(snapshot.docs.map(d => d.data()));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- ACCOUNT ACTIONS ---------------- */
app.post("/api/changePassword", requireAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: "Missing newPassword" });

    await adminAuth.updateUser(req.user.uid, { password: newPassword });
    await logActivity(req.user.uid, "password_changed");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/deleteAccount", requireAuth, async (req, res) => {
  try {
    await adminAuth.deleteUser(req.user.uid);
    await logActivity(req.user.uid, "account_deleted");
    res.clearCookie("session", cookieOpts);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- HELPERS ---------------- */
async function logActivity(uid, type, extra = "") {
  const ref = db.collection("users").doc(uid).collection("activity");
  await ref.add({
    type,
    extra,
    timestamp: new Date().toISOString()
  });
}

/* ---------------- STATIC FILES ---------------- */
const publicDir = path.join(__dirname, "../public");
const privateDir = path.join(__dirname, "../private-views");

app.use(express.static(publicDir));

/* ---------------- PROTECTED VIEWS ---------------- */
app.get("/private/dashboard", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "dashboard.html"))
);
app.get("/private/profile", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "profile.html"))
);
app.get("/private/html", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "html.html"))
);
app.get("/private/css", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "css.html"))
);
app.get("/private/javascript", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "javascript.html"))
);
app.get("/private/cpp", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "cpp.html"))
);
app.get("/private/python", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "python.html"))
);
app.get("/private/tutorials", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "tutorials.html"))
);
app.get("/private/mysql", requireAuth, (_req, res) =>
  res.sendFile(path.join(privateDir, "mysql.html"))
);

/* ---------------- PUBLIC ---------------- */
app.get("/login", (_req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

/* ---------------- FALLBACK ---------------- */
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "Not found" });
  }
  res.sendFile(path.join(publicDir, "index.html"));
});

export default app;
