const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: true,
    },
    enable2FA: {
        type: Boolean,
        default: false,
    },
    memorableInfo: {
        type: String, 
        required: false,
    },
    verified: {
        type: Boolean,
        default: false,
    },
});

// Export the User model
module.exports = mongoose.model('User', userSchema);
