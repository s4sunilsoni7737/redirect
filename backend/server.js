require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs-extra');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const connectDB = require('./config/db');
const { cloudinary } = require('./config/cloudinary');
const Delivery = require('./models/Delivery');

connectDB();

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* ================= SESSION ================= */
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

/* ================= ADMIN CREDENTIALS ================= */
const ADMIN = {
  username: process.env.ADMIN_USERNAME || 'admin',
  // password = admin123
  passwordHash:
    process.env.ADMIN_PASSWORD_HASH ||
    '$2b$10$SfYozai1ipSg4meS6ZIVy.j69cKLslHQolnDikLDoylKa1rMedILK'
};

/* ================= AUTH MIDDLEWARE ================= */
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.redirect('/login');
}

/* ================= MULTER ================= */
const upload = multer({ dest: 'uploads/' });

/* ================= ROUTES ================= */

// Home (verification page)
app.get('/', (req, res) => {
  res.render('index');
});

// Login page (HTML / EJS)
app.get('/login', (req, res) => {
  res.render('login');
});

/* ================= LOGIN API (JSON ONLY) ================= */
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const isUserValid = username === ADMIN.username;
    const isPassValid = await bcrypt.compare(password, ADMIN.passwordHash);

    if (!isUserValid || !isPassValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    /* ✅ SAVE SESSION */
    req.session.authenticated = true;
    req.session.user = { username, role: 'admin' };

    return res.json({
      success: true,
      user: req.session.user
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

/* ================= AUTH STATUS (USED BY LOGIN PAGE) ================= */
app.get('/api/admin/status', (req, res) => {
  res.json({
    authenticated: !!req.session.authenticated,
    user: req.session.user || null
  });
});

// Admin dashboard
app.get('/admin', requireAuth, async (req, res) => {
  const deliveries = await Delivery.find().sort({ createdAt: -1 }).lean();
  res.render('admin', { user: req.session.user, deliveries });
});

// Logout
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

/* ================= CONFIRM API (UNCHANGED) ================= */
app.post(
  '/api/confirm',
  upload.fields([{ name: 'photo' }, { name: 'data' }]),
  async (req, res) => {
    try {
      const encrypted = await fs.readFile(req.files.data[0].path);
      const iv = encrypted.slice(0, 12);
      const authTag = encrypted.slice(-16);
      const enc = encrypted.slice(12, -16);

      const key = Buffer.from(
        'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
      );

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([
        decipher.update(enc),
        decipher.final()
      ]);

      const data = JSON.parse(decrypted.toString());

      const delivery = await Delivery.findOne({
        trackingNumber: data.deliveryId
      });

      if (!delivery)
        return res.status(404).json({ error: 'Delivery not found' });

      const uploadResult = await cloudinary.uploader.upload(
        req.files.photo[0].path,
        { folder: 'deliveries' }
      );

      await fs.unlink(req.files.photo[0].path);
      await fs.unlink(req.files.data[0].path);

      delivery.currentLocation = {
        type: 'Point',
        coordinates: [data.lon, data.lat],
        address: `Lat ${data.lat}, Lng ${data.lon}`,
        timestamp: new Date()
      };

      delivery.images.push({
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        location: {
          type: 'Point',
          coordinates: [data.lon, data.lat],
          address: 'Verified'
        }
      });

      delivery.status = 'delivered';
      await delivery.save();

      res.json({ success: true });

    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal error' });
    }
  }
);

/* ================= SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});