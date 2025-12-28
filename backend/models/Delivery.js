const mongoose = require("mongoose");

const deliverySchema = new mongoose.Schema({
  trackingNumber: { type: String, required: true, unique: true },

  status: {
    type: String,
    enum: ["pending","delivered"],
    default: "pending"
  },

  currentLocation: {
    type: {
      type: String,
      default: "Point"
    },
    coordinates: {
      type: [Number],
      default: [0,0]
    },
    address: {
      type: String,
      default: "Unknown"
    }
  },

  images: [{
    url: String,
    publicId: String,
    location: {
      type: {
        type: String,
        default: "Point"
      },
      coordinates: {
        type: [Number],
        default: [0,0]
      }
    }
  }]

},{ timestamps:true });

deliverySchema.index({ "currentLocation.coordinates":"2dsphere" });

module.exports = mongoose.model("Delivery",deliverySchema);