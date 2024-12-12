const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const rateLimit = require('express-rate-limit');
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

// Rate limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: "Too many login attempts from this IP. Please try again after 15 minutes.",
    },
    standardHeaders: true, 
    legacyHeaders: false,
});


// Registration route
router.post('/register', async (req, res) => {
    const { email, password, confirmPassword, enable2FA, memorableInfo } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        let hashedMemorableInfo = '';
        
        if (enable2FA && memorableInfo) {
            hashedMemorableInfo = await bcrypt.hash(memorableInfo, 10);
        }

        const user = new User({
            email,
            password: hashedPassword,
            enable2FA,
            memorableInfo: enable2FA ? hashedMemorableInfo : undefined,
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

// Send verification OTP to email
const sendVerificationOTPEmail = async ({ _id, email }) => {
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
    } catch (error) {
        console.error("Error sending OTP:", error);
    }
};

// Verification route for OTP
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const otpRecord = await userVerificationOTP.findOne({ userId: user._id });
        if (!otpRecord || Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ message: 'OTP expired' });
        }

        const isValid = await bcrypt.compare(otp, otpRecord.otp);
        if (!isValid) return res.status(400).json({ message: 'Invalid OTP' });

        user.verified = true;
        await user.save();
        await userVerificationOTP.deleteOne({ userId: user._id });

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('OTP Verification Error:', error);
        res.status(500).json({ message: 'An error occurred during OTP verification' });
    }
});

// Login route
router.post('/login', loginLimiter, async (req, res) => {
    const { email, password, memorableInfo } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        if (!user.verified) return res.status(400).json({ message: 'Please verify your email first' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        const isMemorableInfoValid = user.enable2FA ? await bcrypt.compare(memorableInfo, user.memorableInfo) : true;

        if (!isPasswordValid || !isMemorableInfoValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        if (user.enable2FA) {
            await sendVerificationOTPEmail(user);
            return res.json({ success: true, message: '2FA required. New OTP sent.', redirect: '/2fa-verification.html' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, message: 'Login successful', token, redirect: '/homepage.html' });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'An error occurred during login' });
    }
});

// Admin security metrics
router.get('/admin', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const usersWith2FA = await User.countDocuments({ enable2FA: true });
        const failedLoginAttempts = await LoginAttempt.countDocuments({ status: 'failed' });
        const lastUpdate = new Date().toLocaleDateString();

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
