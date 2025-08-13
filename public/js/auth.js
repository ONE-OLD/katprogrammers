import { initializeApp } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-app.js";
import {
  getAuth,
  onIdTokenChanged,
  signInWithEmailAndPassword,
  signOut,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail
} from "https://www.gstatic.com/firebasejs/10.13.1/firebase-auth.js";

// Firebase Web config
const firebaseConfig = {
  apiKey: "AIzaSyD-gCHlAYiX3zJiAeSSSNbQ1qhXJMHLeSQ",
  authDomain: "katprogrammers-1e30e.firebaseapp.com",
  projectId: "katprogrammers-1e30e"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// Keep session cookie fresh
onIdTokenChanged(auth, async (user) => {
  if (user) {
    const idToken = await user.getIdToken(true);
    await fetch("/sessionLogin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    });
  } else {
    await fetch("/sessionLogout", { method: "POST" });
  }
});

// --------- Activity logging helper ---------
async function logActivity(type, extra = "") {
  try {
    const user = auth.currentUser;
    if (!user) return;
    await fetch('/api/logActivity', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid: user.uid, type, extra })
    });
  } catch {}
}

// --------- Expose auth functions globally ---------
window.__auth = {
  auth,

  // LOGIN
  async loginWithEmail(email, password) {
    await signInWithEmailAndPassword(auth, email, password);
    await logActivity('login');
    return true;
  },

  // SIGNUP
  async signupWithEmail(email, password) {
    await createUserWithEmailAndPassword(auth, email, password);
    await logActivity('signup');
    return true;
  },

  // LOGOUT
  async logout() {
    await signOut(auth);
    await logActivity('logout');
  },

  // FORGOT PASSWORD
  async sendResetEmail(email) {
    await sendPasswordResetEmail(auth, email);
    await logActivity('password_reset', email);
  }
};
