// utils/auth.js
import admin from "firebase-admin";

export function initFirebaseAdmin() {
  if (admin.apps.length) return admin;

  if (
    !process.env.FIREBASE_PROJECT_ID ||
    !process.env.FIREBASE_CLIENT_EMAIL ||
    !process.env.FIREBASE_PRIVATE_KEY
  ) {
    throw new Error("Missing Firebase environment variables");
  }

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });

  return admin;
}

export async function createSessionCookie(idToken) {
  const adminApp = initFirebaseAdmin();
  const expiresIn = 5 * 24 * 60 * 60 * 1000; // 5 days

  try {
    return await adminApp.auth().createSessionCookie(idToken, { expiresIn });
  } catch (err) {
    console.error("Failed to create session cookie:", err.message);
    throw err;
  }
}

export async function verifySessionCookie(sessionCookie) {
  const adminApp = initFirebaseAdmin();

  try {
    return await adminApp.auth().verifySessionCookie(sessionCookie, true);
  } catch (err) {
    console.error("Failed to verify session cookie:", err.message);
    throw err;
  }
}
