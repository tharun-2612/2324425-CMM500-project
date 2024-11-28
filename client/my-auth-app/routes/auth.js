const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const User = require('../models/user');
const LoginAttempt = require('../models/LoginAttempt');

const userVerificationOTP = require('../models/userVerificationOTP');
require('dotenv').config();

const router = express.Router();

let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
    },
});

//registration route
router.post('/register', async (req, res) => {
    const { email, password, confirmPassword, enable2FA } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email,
            password: hashedPassword,
            enable2FA,
            verified: !enable2FA,
        });

        await user.save();

        if (enable2FA) {
            await sendVerificationOTPEmail(user);
            return res.status(201).json({ message: 'User registered. Please verify your email.' });
        } else {
            return res.status(201).json({ message: 'User registered successfully. Please log in.' });
        }
    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'An error occurred during registration' });
    }
});


//send verification OTP to email
const sendVerificationOTPEmail = async ({ _id, email }, res) => {
    try {
        const otp = `${Math.floor(1000 + Math.random() * 9000)}`;

        const mailOptions = {
            from: process.env.AUTH_EMAIL,
            to: email,
            subject: "Verify your Email",
            html: `<p>Enter <b>${otp}</b> in the website to verify your email address</p>`,
        };

        const saltRounds = 10;
        const hashedOTP = await bcrypt.hash(otp, saltRounds);
        const newVerificationOTP = new userVerificationOTP({
            userId: _id,
            otp: hashedOTP,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
        });

        await newVerificationOTP.save();

        await transporter.sendMail(mailOptions);

        if (res) {
            res.json({
                status: "pending",
                message: "Verification OTP email sent",
                data: {
                    user_id: _id,
                    email,
                }
            });
        }
    } catch (error) {
        if (res) {
            res.json({
                status: "Failed",
                message: error.message,
            });
        }
    }
};

//verification route
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!email || !otp) {
            console.log("Missing email or OTP:", { email, otp });
            return res.status(400).json({ message: 'Email or OTP missing' });
        }
        
        const otpRecord = await userVerificationOTP.findOne({ userId: user._id });
        if (!otpRecord) {
            console.log("No OTP record found for userId:", user._id);
            return res.status(400).json({ message: 'No OTP record found' });
        }

        if (Date.now() > otpRecord.expiresAt) {
            console.log("OTP expired. Expiration time:", otpRecord.expiresAt);
            await userVerificationOTP.deleteOne({ userId: user._id });
            return res.status(400).json({ message: 'OTP expired' });
        }

        const isValid = await bcrypt.compare(otp, otpRecord.otp);
        console.log("Is OTP valid?", isValid);
        if (!isValid) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        user.verified = true;
        await user.save();

        await userVerificationOTP.deleteOne({ userId: user._id });

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('OTP Verification Error:', error);
        res.status(500).json({ message: 'An error occurred during OTP verification' });
    }
});

//login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        if (!user.verified) return res.status(400).json({ message: 'Please verify your email first' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        if (user.enable2FA) {
            await sendVerificationOTPEmail(user);
            return res.json({ success: true, message: '2FA required. New OTP sent.', redirect: '/2fa-verification.html' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, message: 'Login successful', token, redirect: '/homepage.html' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Admin security metrics
router.get('/admin', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const usersWith2FA = await User.countDocuments({ enable2FA: true });
        const failedLoginAttempts = await LoginAttempt.countDocuments({ status: 'failed' });
        const lastUpdate = new Date().toLocaleDateString(); // Can replace with actual last update timestamp from DB

        res.json({
            totalUsers,
            usersWith2FA,
            failedLoginAttempts,
            lastUpdate
        });
    } catch (error) {
        console.error('Error fetching dashboard metrics:', error);
        res.status(500).json({ message: 'An error occurred while fetching metrics' });
    }
});


module.exports = router;
