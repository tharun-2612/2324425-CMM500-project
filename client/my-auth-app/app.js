const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const authRoutes = require('./routes/auth');

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Routes
app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Registration.html'));
});

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected successfully'))
    .catch((err) => console.error('Database connection error:', err));

// Port Configurations
const PORT_HTTP = process.env.PORT_HTTP || 5001;
const PORT_HTTPS = process.env.PORT_HTTPS || 5443;

// Paths to SSL files (Windows path corrected)
const privateKeyPath = path.join(__dirname, 'ssl', 'private.key');  // Corrected path
const certificatePath = path.join(__dirname, 'ssl', 'certificate.crt');  // Corrected path

// Check if SSL files exist and create the HTTPS server if they do
let sslOptions = null;
if (fs.existsSync(privateKeyPath) && fs.existsSync(certificatePath)) {
    sslOptions = {
        key: fs.readFileSync(privateKeyPath),
        cert: fs.readFileSync(certificatePath),
    };
    
    https.createServer(sslOptions, app).listen(PORT_HTTPS, () => {
        console.log(`HTTPS Server running on https://localhost:${PORT_HTTPS}`);
    });
} else {
    console.warn('SSL files not found. HTTPS server will not be started.');
}

// HTTP Server
http.createServer(app).listen(PORT_HTTP, () => {
    console.log(`HTTP Server running on http://localhost:${PORT_HTTP}`);
});
