// utils/auth.js
import admin from "firebase-admin";

let initialized = false;

export function initFirebaseAdmin() {
  if (initialized) return admin;

  if (!admin.apps.length) {
    if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
      throw new Error("Missing Firebase environment variables");
    }

    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
      })
    });
  }

  initialized = true;
  return admin;
}

export async function verifySessionCookie(sessionCookie) {
  const a = initFirebaseAdmin();
  return a.auth().verifySessionCookie(sessionCookie, true);
}

export async function createSessionCookie(idToken) {
  const a = initFirebaseAdmin();
  const expiresIn = 1000 * 60 * 60 * 24 * 5; // 5 days
  return a.auth().createSessionCookie(idToken, { expiresIn });
}
