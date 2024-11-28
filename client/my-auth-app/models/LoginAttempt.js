const mongoose = require('mongoose');

const loginAttemptSchema = new mongoose.Schema({
    email: { type: String, required: true },
    status: { type: String, required: true, enum: ['failed', 'successful'] },
    timestamp: { type: Date, default: Date.now }
});

const LoginAttempt = mongoose.model('LoginAttempt', loginAttemptSchema);

module.exports = LoginAttempt;
