import admin from "firebase-admin";

let initialized = false;

export function initFirebaseAdmin() {
  if (initialized) return admin;

  // Prefer env vars (recommended in Vercel) — else fallback to JSON file if present
  const useEnv = !!process.env.FIREBASE_PROJECT_ID;

  if (!admin.apps.length) {
    if (useEnv) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          // Private key may contain \n that need replacing when stored as an env var
          privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n")
        })
      });
    } else {
      // Fallback to JSON file (local dev). Do NOT commit this to git.
      const serviceAccount = await import("../../firebase-service-account.json", { assert: { type: "json" } });
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount.default)
      });
    }
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
  // Example: 5 days max for session cookie
  const expiresIn = 1000 * 60 * 60 * 24 * 5;
  return a.auth().createSessionCookie(idToken, { expiresIn });
}
