require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const stream = require('stream');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
// Import Cloudinary configuration
const { cloudinary } = require('./config/cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const connectDB = require('./config/db');

// Connect to MongoDB
connectDB().catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Get the default connection
const db = mongoose.connection;

// Bind connection to error event (to get notification of connection errors)
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Successfully connected to MongoDB');
});

const Delivery = require('./models/Delivery');
const app = express();

// Admin credentials
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || 'sunil123',
  // Password: sunil@123 (hashed with bcrypt)
  passwordHash: process.env.ADMIN_PASSWORD_HASH || '$2b$10$SfYozai1ipSg4meS6ZIVy.j69cKLslHQolnDikLDoylKa1rMedILK' 
};

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  }
  
  // For API requests, return JSON error
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // For web routes, redirect to login
  res.redirect('/login');
};

// Create a test delivery
app.post('/api/test-delivery', requireAuth, async (req, res) => {
  try {
    const testDelivery = await Delivery.createWithTrackingNumber({
      currentLocation: {
        type: 'Point',
        coordinates: [77.5946, 12.9716], // Bangalore coordinates
        address: 'Test Location, Bangalore',
        timestamp: new Date()
      },
      status: 'in_transit',
      images: [{
        url: 'https://res.cloudinary.com/demo/image/upload/sample.jpg',
        publicId: 'test-delivery-1',
        timestamp: new Date(),
        location: {
          type: 'Point',
          coordinates: [77.5946, 12.9716],
          address: 'Test Location, Bangalore'
        }
      }],
      createdBy: req.session.user._id || new mongoose.Types.ObjectId()
    });
    
    res.json({
      success: true,
      message: 'Test delivery created successfully!',
      delivery: testDelivery
    });
  } catch (error) {
    console.error('Error creating test delivery:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating test delivery',
      error: error.message
    });
  }
});

// Test route to check MongoDB connection and data access
app.get('/api/test', async (req, res) => {
  try {
    // First, try to count existing deliveries
    const count = await Delivery.countDocuments();
    
    // If no deliveries exist, create a test one
    if (count === 0) {
      console.log('No deliveries found, creating test delivery...');
      const testDelivery = await Delivery.createWithTrackingNumber({
        currentLocation: {
          type: 'Point',
          coordinates: [0, 0],
          address: 'Test Location',
          timestamp: new Date()
        },
        status: 'in_transit',
        images: [{
          url: 'https://via.placeholder.com/300',
          publicId: 'test-image-1',
          timestamp: new Date(),
          location: {
            type: 'Point',
            coordinates: [0, 0],
            address: 'Test Location'
          }
        }],
        createdBy: new mongoose.Types.ObjectId()
      });
      
      return res.json({
        success: true,
        message: 'Test delivery created successfully!',
        delivery: testDelivery
      });
    }
    
    // If deliveries exist, return the count and first few
    const deliveries = await Delivery.find().limit(5).lean();
    
    res.json({
      success: true,
      message: `Found ${count} delivery records`,
      count,
      sample: deliveries
    });
  } catch (error) {
    console.error('Test route error:', error);
    res.status(500).json({
      success: false,
      message: 'Error connecting to MongoDB',
      error: error.message
    });
  }
});

// Set up EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configure security headers
app.use(helmet({
  contentSecurityPolicy: false,   // Disable CSP as we're setting it in the views
  hsts: true,
  noSniff: true,
  xssFilter: true
}));

// Trust first proxy if behind a reverse proxy (e.g., nginx, heroku)
app.set('trust proxy', 1);

const corsOptions = {
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// Session configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your-secret-key-123',
  resave: true,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/'
  },
  rolling: true // Reset maxAge on every request
};

// Use MongoDB for session store in production
if (process.env.NODE_ENV === 'production') {
  try {
    const MongoStore = require('connect-mongo');

    sessionConfig.store = MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions',
      ttl: 24 * 60 * 60
    });

    console.log('✅ Using MongoDB session store');
  } catch (err) {
    console.warn(
      '⚠️ MongoDB session store failed, using memory store:',
      err.message
    );
  }
}

app.use(session(sessionConfig));


// Logout route
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check auth status
app.get('/api/admin/status', (req, res) => {
  res.json({ 
    authenticated: !!(req.session && req.session.authenticated),
    user: req.session?.user || null
  });
});


const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.ensureDirSync(UPLOAD_DIR);

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  extensions: ['html', 'js', 'css']
}));

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

// 1. API Routes
app.post('/api/admin/login', express.json(), async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const isValidUser = username === ADMIN_CREDENTIALS.username;
    const isValidPassword = await bcrypt.compare(password, ADMIN_CREDENTIALS.passwordHash);

    if (isValidUser && isValidPassword) {
      // Regenerate session to prevent session fixation
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        
        // Store user information in the session
        req.session.authenticated = true;
        req.session.user = { 
          _id: new mongoose.Types.ObjectId(),
          username: username,
          role: 'admin'
        };
        
        // Save the session before sending the response
        req.session.save((err) => {
          if (err) {
            console.error('Session save error:', err);
            return res.status(500).json({ error: 'Failed to save session' });
          }
          
          // Send response with user info
          res.json({ 
            success: true,
            user: {
              id: req.session.user._id,
              username: req.session.user.username,
              role: req.session.user.role
            }
          });
        });
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Serve uploads directory with authentication
app.use('/uploads', requireAuth, express.static(UPLOAD_DIR, {
  maxAge: '7d'
}));

const upload = multer({
  storage,
  limits: { fileSize: 6 * 1024 * 1024 }, // 6MB
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'photo' && !file.mimetype.startsWith('image/')) {
      return cb(new Error('Only images are allowed for photo upload'));
    }
    cb(null, true);
  }
});

// Add a middleware to parse multipart form data
const uploadFields = upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'data', maxCount: 1 }
]);

// Add crypto module at the top of the file if not already present
const crypto = require('crypto');

app.post('/api/confirm', uploadFields, async (req, res) => {
  console.log('Received request to /api/confirm');
  
  try {
    // Check if photo was uploaded
    const hasPhoto = req.files && req.files.photo && Array.isArray(req.files.photo) && req.files.photo.length > 0;
    let file = hasPhoto ? req.files.photo[0] : null;
    
    if (!hasPhoto) {
      console.log('No photo uploaded, proceeding with location data only');
    }

    // If we have a file, validate it
    if (hasPhoto) {
      if (!file || !file.path) {
        console.error('Invalid file object');
        return res.status(400).json({ 
          success: false,
          error: "Invalid file upload" 
        });
      }
    }

    // Get the encrypted data
    let decryptedData = {};
    if (req.files.data && req.files.data[0]) {
      try {
        const dataFile = req.files.data[0];
        let encryptedData;
        
        // Get the buffer from either buffer or file path
        if (dataFile.buffer) {
          encryptedData = dataFile.buffer;
        } else if (dataFile.path) {
          encryptedData = await fs.readFile(dataFile.path);
        }
        
        if (encryptedData) {
          console.log('Encrypted data received. Length:', encryptedData.length);
          
          // The first 12 bytes are the IV
          const iv = encryptedData.slice(0, 12);
          // The rest is the encrypted data + auth tag (last 16 bytes)
          const authTag = encryptedData.slice(-16);
          const encrypted = encryptedData.slice(12, -16);
          
          // Ensure key is exactly 32 bytes (256 bits)
          const ENCRYPTION_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
          const keyBuffer = Buffer.from(ENCRYPTION_KEY, 'utf8').slice(0, 32);
          
          console.log('IV length:', iv.length, 'Encrypted data length:', encrypted.length, 'Auth tag length:', authTag.length);
          
          // Create decipher
          const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            keyBuffer,
            iv
          );
          
          // Set the auth tag
          decipher.setAuthTag(authTag);
          
          // Decrypt the data
          let decrypted = decipher.update(encrypted);
          decrypted = Buffer.concat([decrypted, decipher.final()]);
          
          // Parse the decrypted JSON
          decryptedData = JSON.parse(decrypted.toString('utf8'));
          console.log('Successfully decrypted data:', decryptedData);
        } else {
          console.error('No encrypted data found in the request');
          throw new Error('No encrypted data found');
        }
      } catch (decryptError) {
        console.error('Error decrypting data:', decryptError);
        return res.status(400).json({ 
          success: false,
          error: `Decryption failed: ${decryptError.message}`
        });
      }
    }

    // Handle image upload if present
    let imageUrl = '';
    if (hasPhoto) {
      try {
        // First, check if we have the file buffer
        if (!file.buffer && file.path) {
          // If no buffer but we have a path, read the file
          file.buffer = await fs.readFile(file.path);
        }

        if (!file.buffer) {
          throw new Error('No file data available for upload');
        }

        // Convert buffer to base64
        const base64Data = file.buffer.toString('base64');
        const dataUri = `data:${file.mimetype};base64,${base64Data}`;
        
        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(dataUri, {
          folder: 'fraud-detection',
          resource_type: 'auto',
          use_filename: true,
          unique_filename: true
        });
        
        imageUrl = result.secure_url;
        console.log('Successfully uploaded to Cloudinary:', imageUrl);
        
        // Remove the temporary file if it exists
        if (file.path && fs.existsSync(file.path)) {
          await fs.unlink(file.path).catch(console.error);
        }
      } catch (uploadError) {
        console.error('Error uploading to Cloudinary:', uploadError);
        // Don't fail the entire request if image upload fails
        // Continue with location data only
        console.log('Proceeding without image due to upload error');
      }
    }

    // Parse and validate location data
    const deliveryId = decryptedData.deliveryId || req.query.deliveryId || "unknown";
    const token = decryptedData.token || req.query.token || "";
    
    // Parse and validate latitude and longitude
    let lat = null;
    let lon = null;
    
    if (decryptedData.lat !== undefined && decryptedData.lon !== undefined) {
      lat = parseFloat(decryptedData.lat);
      lon = parseFloat(decryptedData.lon);
      
      // Validate coordinates
      if (isNaN(lat) || isNaN(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
        console.error('Invalid coordinates:', { lat, lon });
        return res.status(400).json({
          success: false,
          error: 'Invalid coordinates provided',
          details: `Latitude must be between -90 and 90, Longitude between -180 and 180. Got: ${lat}, ${lon}`
        });
      }
    } else {
      console.error('Missing coordinates in request');
      return res.status(400).json({
        success: false,
        error: 'Missing coordinates',
        details: 'Both lat and lon are required'
      });
    }
    
    const accuracy = decryptedData.accuracy ? parseFloat(decryptedData.accuracy) : null;
    const locTimestamp = decryptedData.timestamp ? new Date(parseInt(decryptedData.timestamp)) : new Date();
    const userAgent = decryptedData.userAgent || req.get("User-Agent");

    // Format address for better display
    const address = `Lat: ${lat.toFixed(6)}, Lng: ${lon.toFixed(6)}`;
    
    const meta = {
      deliveryId,
      file: file.filename,
      imageUrl,
      lat,
      lon,
      accuracy,
      locTimestamp: locTimestamp.getTime(),
      receivedAt: Date.now(),
      ip: req.ip,
      userAgent,
      token
    };

    // No need to save to local filesystem anymore
    console.log('Image uploaded to Cloudinary:', imageUrl);

    // Create delivery record in MongoDB
    try {
      // Prepare base delivery data
      const deliveryData = {
        currentLocation: {
          type: 'Point',
          coordinates: [lon, lat], // MongoDB GeoJSON: [longitude, latitude]
          address: address,
          timestamp: locTimestamp,
          accuracy: accuracy
        },
        status: 'delivered',
        createdBy: req.session.userId || new mongoose.Types.ObjectId()
      };
      
      // Add image data if available
      if (imageUrl) {
        deliveryData.images = [{
          url: imageUrl,
          publicId: `delivery-${Date.now()}`,
          timestamp: new Date(),
          location: {
            type: 'Point',
            coordinates: [lon, lat],
            address: address
          }
        }];
      }
      
      console.log('Creating delivery with data:', JSON.stringify(deliveryData, null, 2));
      
      const delivery = await Delivery.createWithTrackingNumber(deliveryData);

      console.log('Delivery created in MongoDB:', delivery);
      
      return res.json({ 
        success: true,
        message: "Delivery confirmed and saved successfully",
        deliveryId: delivery._id,
        trackingNumber: delivery.trackingNumber,
        meta 
      });
    } catch (dbError) {
      console.error('Error saving to MongoDB:', dbError);
      // Still return success since the file was uploaded and saved
      return res.status(500).json({
        success: true, // Still success because file was uploaded
        warning: 'Delivery confirmed but could not save to database',
        error: dbError.message,
        meta
      });
    }

  } catch (err) {
    console.error('Error in /api/confirm:', err);
    console.error('Error stack:', err.stack);
    return res.status(500).json({ 
      error: "Internal server error",
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Handle 404 for all other routes
app.get('/', (req, res) => {
  res.render('index', { 
    title: 'Delivery Verification',
    env: process.env.NODE_ENV || 'development'
  });
});

app.get('/confirm', (req, res) => {
  res.render('confirm', {
    title: 'Delivery Confirmation',
    deliveryId: req.query.deliveryId || 'unknown',
    token: req.query.token || ''
  });
});

app.get('/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/admin');
  }
  res.render('login', { error: req.query.error });
});

// Admin dashboard route
app.get('/admin', requireAuth, async (req, res) => {
  try {
    console.log('Fetching deliveries from database...');
    // Fetch all deliveries with their images, sorted by creation date (newest first)
    const deliveries = await Delivery.find({})
      .sort({ createdAt: -1 }) // Sort by newest first
      .lean(); // Convert to plain JavaScript objects

    console.log(`Found ${deliveries.length} deliveries`);
    res.render('admin', { 
      user: req.session.user,
      deliveries: deliveries || []
    });
  } catch (error) {
    console.error('Error fetching deliveries:', error);
    res.status(500).render('error', { 
      message: 'Error loading admin dashboard',
      error: process.env.NODE_ENV === 'development' ? error : {}
    });
  }
});

// Login page route
app.get('/login', (req, res) => {
  // If already logged in, redirect to admin
  if (req.session?.authenticated) {
    return res.redirect('/admin');
  }
  res.render('login', { message: null, error: null });
});

// Error handling for 404
app.use((req, res, next) => {
  res.status(404).send("Sorry, can't find that!");
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  
  // Set locals, only providing error in development
  const errorDetails = process.env.NODE_ENV === 'development' ? err.stack : {};
  
  // Render the error page
  res.status(err.status || 500);
  res.render('error', {
    title: 'Error',
    message: err.message,
    error: errorDetails
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Upload directory: ${UPLOAD_DIR}`);
  console.log('Press Ctrl+C to stop the server');
});
