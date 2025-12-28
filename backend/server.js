require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const connectDB = require('./config/db');
const { cloudinary } = require('./config/cloudinary');
const Delivery = require('./models/Delivery');

connectDB();

const app = express();
app.set('view engine','ejs');
app.set('views',path.join(__dirname,'views'));

const upload = multer({ dest:'uploads/' });

/* HOME */
app.get('/', (req,res)=>{
  res.render('index');
});

/* CONFIRM API */
app.post('/api/confirm', upload.single('photo'), async (req,res)=>{
  try {
    const { deliveryId, lat, lon } = req.body;

    if(!deliveryId) return res.status(400).json({success:false});

    let delivery = await Delivery.findOne({ trackingNumber: deliveryId });
    if(!delivery){
      delivery = await Delivery.createWithTrackingNumber({});
    }

    const result = await cloudinary.uploader.upload(req.file.path,{
      folder:'deliveries'
    });

    await fs.unlink(req.file.path);

    delivery.currentLocation = {
      type:'Point',
      coordinates:[Number(lon),Number(lat)],
      address:`Lat ${lat}, Lng ${lon}`
    };

    delivery.images.push({
      url: result.secure_url,
      publicId: result.public_id,
      location:{
        type:'Point',
        coordinates:[Number(lon),Number(lat)],
        address:'Verified'
      }
    });

    delivery.status='delivered';
    await delivery.save();

    res.json({success:true});
  }
  catch(err){
    console.error(err);
    res.status(500).json({success:false});
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 Server running on ${PORT}`));