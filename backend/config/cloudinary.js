const cloudinary = require('cloudinary').v2;

// Configure Cloudinary with your credentials
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// Upload file to Cloudinary
const uploadToCloudinary = async (filePath, folder = 'fraud-detection') => {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: 'fraud-detection',
      resource_type: 'auto',
      use_filename: true,
      unique_filename: true
    });
    return result.secure_url; // Return the secure URL of the uploaded file
  } catch (error) {
    console.error('Error uploading to Cloudinary:', error);
    throw error;
  }
};

module.exports = {
  cloudinary,
  uploadToCloudinary
};
