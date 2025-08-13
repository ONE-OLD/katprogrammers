import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import admin from "firebase-admin";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

// Fix __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Paths
const publicDir = path.join(__dirname, "../public");
const privateDir = path.join(__dirname, "../private-views");

// Firebase Admin SDK
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../firebase-service-account.json"))
  );
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json());

// Serve static public files
app.use(express.static(publicDir));

// Auth middleware
async function checkAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.redirect("/login.html");

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect("/login.html");
  }
}

// Public route
app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

// Private route
app.get("/dashboard", checkAuth, (req, res) => {
  res.sendFile(path.join(privateDir, "dashboard.html"));
});

// API endpoint to set cookie after login
app.post("/login", async (req, res) => {
  const { token } = req.body;
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "strict" });
    res.json({ message: "Logged in", user: decoded });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

export default app;
