
const User = require('../models/user');
const OTP = require('../models/otp');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Email Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


// 1. REGISTER
const register = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                message: 'All required fields are necessary'
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(409).json({
                message: 'Email already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            username,
            email,
            password: hashedPassword
        });

        // Generate OTP
        const otp = crypto.randomInt(100000, 1000000).toString();

        const hashedOTP = await bcrypt.hash(otp, 10);

        const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

        await OTP.create({
            userId: user._id,
            otp: hashedOTP,
            otpExpiry
        });

        // Send Email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Email Verification OTP',
            text: `Your OTP is ${otp}. It expires in 5 minutes.`
        });

        res.status(201).json({
            message: 'Registration successful. OTP sent to email.',
            userId: user._id
        });

    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: 'Registration failed'
        });
    }
};


// 2. VERIFY OTP
const verifyOTP = async (req, res) => {
    try {
        const { userId, otp } = req.body;

        if (!userId || !otp) {
            return res.status(400).json({
                message: 'User ID and OTP are required'
            });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        if (user.isVerified) {
            return res.status(400).json({
                message: 'Email already verified'
            });
        }

        const otpRecord = await OTP.findOne({ userId });

        if (!otpRecord) {
            return res.status(404).json({
                message: 'OTP not found'
            });
        }

        if (otpRecord.otpExpiry <= new Date()) {
            await OTP.deleteOne({ _id: otpRecord._id });

            return res.status(400).json({
                message: 'OTP expired'
            });
        }

        const isMatch = await bcrypt.compare(
            otp,
            otpRecord.otp
        );

        if (!isMatch) {
            return res.status(400).json({
                message: 'Invalid OTP'
            });
        }

        user.isVerified = true;
        await user.save();

        await OTP.deleteOne({ _id: otpRecord._id });

        res.status(200).json({
            message: 'Email verified successfully'
        });

    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: 'OTP verification failed'
        });
    }
};


// 3. LOGIN
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        if (!user.isVerified) {
            return res.status(403).json({
                message: 'Please verify your email first'
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(401).json({
                message: 'Incorrect password'
            });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email
            },
            process.env.JWT_SECRET,
            {
                expiresIn: '1d'
            }
        );

        res.status(200).json({
            message: 'Login successful',
            token
        });

    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: 'Login failed'
        });
    }
};


// 4. GET PROFILE
const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('-password');

        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        res.status(200).json({
            message: 'Profile fetched successfully',
            user
        });

    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: 'Profile fetch failed'
        });
    }
};


// 5. LOGOUT
const logout = (req, res) => {
    res.status(200).json({
        message: 'Logout successful. Remove your token from client storage.'
    });
};


// Export Controllers
module.exports = {
    register,
    verifyOTP,
    login,
    getProfile,
    logout
};
