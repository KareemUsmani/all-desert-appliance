
const express = require('express');
const router = express.Router();

const {
    register,
    verifyOTP,
    login,
    getProfile,
    logout
} = require('../controller/authController');

const authMiddleware = require('../utils/authMiddleware');

// Authentication Routes
router.post('/register', register);

router.post('/verify-otp', verifyOTP);

router.post('/login', login);

router.get('/profile', authMiddleware, getProfile);

router.post('/logout', logout);

module.exports = router;
