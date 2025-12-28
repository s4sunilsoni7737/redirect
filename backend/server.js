require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs-extra');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');

const connectDB = require('./config/db');
const { cloudinary } = require('./config/cloudinary');
const Delivery = require('./models/Delivery');

connectDB();

const app = express();
app.set('view engine','ejs');
app.set('views',path.join(__dirname,'views'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

const upload = multer({ dest:'uploads/' });

app.get('/', (req,res)=>res.render('index'));

/* ================= CONFIRM API ================= */

app.post('/api/confirm',
  upload.fields([{ name:'photo' },{ name:'data' }]),
  async (req,res)=>{
    try {
      /* ---- decrypt ---- */
      const encrypted = await fs.readFile(req.files.data[0].path);
      const iv = encrypted.slice(0,12);
      const authTag = encrypted.slice(-16);
      const enc = encrypted.slice(12,-16);

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

      /* ---- find delivery ---- */
      const delivery = await Delivery.findOne({
        trackingNumber: data.deliveryId
      });

      if (!delivery)
        return res.status(404).json({ error:'Delivery not found' });

      /* ---- upload image ---- */
      const uploadResult = await cloudinary.uploader.upload(
        req.files.photo[0].path,
        { folder:'deliveries' }
      );

      await fs.unlink(req.files.photo[0].path);
      await fs.unlink(req.files.data[0].path);

      /* ---- update ---- */
      delivery.currentLocation = {
        type:'Point',
        coordinates:[data.lon, data.lat],
        address:`Lat ${data.lat}, Lng ${data.lon}`,
        timestamp:new Date()
      };

      delivery.images.push({
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id,
        location:{
          type:'Point',
          coordinates:[data.lon, data.lat],
          address:'Verified'
        }
      });

      delivery.status = 'delivered';
      await delivery.save();

      res.json({ success:true });
    }
    catch(err){
      console.error(err);
      res.status(500).json({ error:'Internal error' });
    }
  }
);

app.listen(process.env.PORT, ()=>{
  console.log(`🚀 Server running on ${process.env.PORT}`);
});