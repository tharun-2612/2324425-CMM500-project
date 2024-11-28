const mongoose = require("mongoose")
const Schema = mongoose.Schema;

const userVerificationOTPSchema = new Schema({
    userId: String,
    otp: String,
    createdAt: Date,
    expiresAt: Date,
});

const userVerificationOTP = mongoose.model(
    "userverificationOTP",
    userVerificationOTPSchema
);

module.exports = userVerificationOTP;