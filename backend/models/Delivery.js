const mongoose = require('mongoose');

const deliverySchema = new mongoose.Schema({
  // Basic delivery information
  trackingNumber: {
    type: String,
    required: true,
    unique: true
  },
  status: {
    type: String,
    enum: ['pending', 'in_transit', 'delivered', 'failed'],
    default: 'pending'
  },
  
  // Location information
  currentLocation: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true
    },
    address: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  },
  
  // Image information
  images: [{
    url: {
      type: String,
      required: true
    },
    publicId: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    location: {
      type: {
        type: String,
        enum: ['Point'],
        default: 'Point'
      },
      coordinates: {
        type: [Number],
        required: true
      },
      address: String
    }
  }],
  
  // Additional metadata
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  
  // Reference to the user/agent who created/updated the delivery
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Create 2dsphere index for geospatial queries
deliverySchema.index({ 'currentLocation.coordinates': '2dsphere' });
deliverySchema.index({ 'images.location.coordinates': '2dsphere' });

// Static method to create a new delivery with a unique tracking number
deliverySchema.statics.createWithTrackingNumber = async function(deliveryData) {
  const count = await this.countDocuments();
  const trackingNumber = `DLV-${Date.now()}-${count.toString().padStart(6, '0')}`;
  return this.create({ ...deliveryData, trackingNumber });
};

// Method to add a new image to a delivery
deliverySchema.methods.addImage = function(imageData) {
  this.images.push(imageData);
  return this.save();
};

// Method to update the current location
deliverySchema.methods.updateLocation = function(locationData) {
  this.currentLocation = {
    type: 'Point',
    coordinates: [locationData.longitude, locationData.latitude],
    address: locationData.address,
    timestamp: new Date()
  };
  return this.save();
};

const Delivery = mongoose.model('Delivery', deliverySchema);

module.exports = Delivery;
