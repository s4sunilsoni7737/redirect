const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: false,   // Disable CSP
  })
);
// Configure CORS with preflight support
const corsOptions = {
  origin: [
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "https://yourapp.onrender.com",
    "https://*.ngrok-free.dev"
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// Allow credentials for CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.ensureDirSync(UPLOAD_DIR);

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),

  filename: (req, file, cb) => {
    // Protect against undefined req.body
    const body = req.body || {};

    const id = (body.deliveryId || 'unknown').replace(/[^a-zA-Z0-9-_]/g, '_');
    const ts = Date.now();

    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${id}-${ts}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only images allowed'));
    cb(null, true);
  }
});

app.post('/api/confirm', upload.single('photo'), async (req, res) => {
  try {
    // SAFE READ
    const body = req.body || {};          // <---- FIX
    const token = body.token || "";       // <---- FIX
    const deliveryId = body.deliveryId || "unknown";
    
    const file = req.file;
    if (!file) return res.status(400).send("No photo uploaded");

    const lat = parseFloat(body.lat) || null;
    const lon = parseFloat(body.lon) || null;
    const accuracy = body.accuracy || null;
    const locTimestamp = Number(body.locTimestamp) || Date.now();

    const meta = {
      deliveryId,
      file: file.filename,
      lat,
      lon,
      accuracy,
      locTimestamp,
      receivedAt: Date.now(),
      ip: req.ip,
      userAgent: req.get("User-Agent")
    };

    await fs.writeJson(
      path.join(UPLOAD_DIR, file.filename + ".json"),
      meta,
      { spaces: 2 }
    );

    return res.json({ ok: true, meta });

  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error: " + err.message);
  }
});

// serve uploads (only for admin with auth - here for quick test)
app.use('/uploads', express.static(UPLOAD_DIR));

// API to list all delivery confirmations
app.get('/api/list', async (req, res) => {
  try {
    const files = await fs.readdir(UPLOAD_DIR);

    // Only JSON meta files
    const metaFiles = files.filter(f => f.endsWith('.json'));

    const items = [];
    for (const metaFile of metaFiles) {
      const metaPath = path.join(UPLOAD_DIR, metaFile);
      const meta = await fs.readJson(metaPath);

      // Add image URL
      meta.imageUrl = `/uploads/${meta.file}`;

      items.push(meta);
    }

    // Sort newest first
    items.sort((a, b) => b.receivedAt - a.receivedAt);

    res.json({ ok: true, items });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error reading uploads");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server listening on port', PORT));
