import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { initFirebaseAdmin, verifySessionCookie, createSessionCookie } from "./utils/auth.js";

// Initialize Firebase Admin once
initFirebaseAdmin();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json());

// Paths
const publicDir = path.join(__dirname, "../public");
const privateDir = path.join(__dirname, "../private-views");

// Helper: cookie options
const isProd = process.env.NODE_ENV === "production";
const cookieOpts = {
  httpOnly: true,
  secure: isProd,                  // on Vercel this will be true
  sameSite: "strict",
  path: "/"
};

// ---- Auth middleware (session cookie) ----
async function requireAuth(req, res, next) {
  const sessionCookie = req.cookies.session || null;
  if (!sessionCookie) return res.redirect("/login.html");

  try {
    const decoded = await verifySessionCookie(sessionCookie);
    req.user = decoded;
    return next();
  } catch (e) {
    return res.redirect("/login.html");
  }
}

// ---- API endpoints ----
// Exchange Firebase ID token (from client) -> Session cookie
app.post("/sessionLogin", async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ error: "Missing idToken" });

  try {
    const sessionCookie = await createSessionCookie(idToken);
    res.cookie("session", sessionCookie, cookieOpts);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/sessionLogout", async (_req, res) => {
  res.clearCookie("session", { path: "/" });
  return res.json({ ok: true });
});

// Who am I? (example protected API)
app.get("/api/me", requireAuth, (req, res) => {
  return res.json({ uid: req.user.uid, email: req.user.email, name: req.user.name || null });
});

// ---- Static + routes ----
// Serve public assets
app.use(express.static(publicDir));

// Protected pages
app.get("/dashboard", requireAuth, (_req, res) => {
  return res.sendFile(path.join(privateDir, "dashboard.html"));
});

// Optional additional protected routes
// app.get("/profile", requireAuth, ...)

// SPA fallback: any other GET -> index.html (keep last)
app.get("*", (req, res) => {
  // If file exists physically in public, serve it
  const potentialFile = path.join(publicDir, req.path);
  if (fs.existsSync(potentialFile) && fs.statSync(potentialFile).isFile()) {
    return res.sendFile(potentialFile);
  }
  // else send index.html
  return res.sendFile(path.join(publicDir, "index.html"));
});

export default app;
