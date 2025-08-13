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

// Expose auth functions globally
window.__auth = {
  auth,

  // LOGIN
  async loginWithEmail(email, password) {
    await signInWithEmailAndPassword(auth, email, password);
    return true;
  },

  // SIGNUP
  async signupWithEmail(email, password) {
    await createUserWithEmailAndPassword(auth, email, password);
    return true;
  },

  // LOGOUT
  async logout() {
    await signOut(auth);
  },

  // FORGOT PASSWORD
  async sendResetEmail(email) {
    await sendPasswordResetEmail(auth, email);
  }
};
