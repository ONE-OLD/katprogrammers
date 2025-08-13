import { initializeApp } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-app.js";
  import { getAuth, onIdTokenChanged, signInWithEmailAndPassword, signOut } from "https://www.gstatic.com/firebasejs/10.13.1/firebase-auth.js";

  // TODO: replace with your project config
  const firebaseConfig = {
    apiKey: "AIzaSyD-gCHlAYiX3zJiAeSSSNbQ1qhXJMHLeSQ",
    authDomain: "katprogrammers-1e30e.firebaseapp.com",
    projectId: "katprogrammers-1e30e"
  };

  const app = initializeApp(firebaseConfig);
  const auth = getAuth(app);

  // Keep session cookie fresh: whenever ID token changes, refresh session cookie
  onIdTokenChanged(auth, async (user) => {
    if (user) {
      const idToken = await user.getIdToken(/* forceRefresh */ true);
      await fetch('/sessionLogin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      });
    } else {
      await fetch('/sessionLogout', { method: 'POST' });
    }
  });

  // Helpers to expose globally (optional)
  window.__auth = {
    auth,
    async loginWithEmail(email, password) {
      await signInWithEmailAndPassword(auth, email, password);
      // server cookie sets via onIdTokenChanged
      return true;
    },
    async logout() {
      await signOut(auth); // server cookie cleared via onIdTokenChanged
    }
  };

