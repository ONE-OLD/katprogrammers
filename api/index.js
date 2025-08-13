const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const serverless = require('serverless-http');

const app = express();
const router = express.Router();

// ======================
// Middleware Configuration
// ======================
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// ======================
// Firebase Initialization
// ======================
if (!admin.apps.length) {
  try {
    const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n') || '';
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: privateKey
      })
    });
    console.log('Firebase initialized successfully');
  } catch (error) {
    console.error('Firebase init error:', error);
  }
}

// ======================
// Authentication Middleware
// ======================
async function checkAuth(req, res, next) {
  const sessionCookie = req.cookies.session || '';
  if (!sessionCookie) return res.redirect('/');
  try {
    await admin.auth().verifySessionCookie(sessionCookie, true);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
  } catch (error) {
    console.error('Auth error:', error);
    res.redirect('/');
  }
}

// ======================
// Route Definitions
// ======================

// Home Route
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

// Auth Endpoints
router.post('/sessionLogin', async (req, res) => {
  const idToken = req.body.idToken;
  const expiresIn = 60 * 60 * 24 * 5 * 1000; // 5 days
  
  try {
    const sessionCookie = await admin.auth().createSessionCookie(idToken, { expiresIn });
    
    res.cookie('session', sessionCookie, {
      maxAge: expiresIn,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/'
    });
    
    res.json({ status: 'success' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: 'UNAUTHORIZED' });
  }
});

router.get('/sessionLogout', (req, res) => {
  res.clearCookie('session', {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  });
  res.redirect('/');
});

// Protected Routes
const protectedPages = [
  'dashboard',
  'apps',
  'tutorials',
  'html',
  'css',
  'javascript',
  'python',
  'cpp',
  'mysql',
  'profile',
  'news',
  'certificate',
  'account'
];

protectedPages.forEach(page => {
  router.get(`/${page}`, checkAuth, (req, res) => {
    try {
      res.sendFile(path.join(__dirname, '../private-views', `${page}.html`));
    } catch (error) {
      console.error(`Error loading ${page}:`, error);
      res.status(404).send('Page not found');
    }
  });
});

// ======================
// Serverless Configuration
// ======================
app.use('/api', router);  // Primary Vercel endpoint
app.use('/', router);     // Fallback for direct access

module.exports.handler = serverless(app, {
  binary: [
    'image/*',
    'application/javascript',
    'application/json',
    'text/css'
  ]
});