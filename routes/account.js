const express = require('express');
const User = require('../models/user');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const verifyAdmin = require('../middlewares/verifyAdmin');
const isAuthenticated = require('../middlewares/isAuthenticate');


const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    onLimitReached: (req, res, options) => {
        console.log(`Tentatives de connexion épuisées pour l'IP ${req.ip}`);
    }
});


router.post('/account', verifyAdmin, async (req, res) => {
    const { login, password, role, status } = req.body;

    try {
        const existingUser = await User.findOne({ login });
        if (existingUser) 
            return res.status(409).json({ message: "User already exists." });
        

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            login,
            password: hashedPassword,
            role,
            status,
            created_at: new Date()
        });

        await user.save();

        res.status(201).json({
            uid: user._id,
            login: user.login,
            role: user.role,
            status: user.status,
            created_at: user.created_at
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error." });
    }
});

router.get('/account/:uid', isAuthenticated, async (req, res) => {
    try {
        const { uid } = req.params;
        const userId = uid === 'me' ? req.user.userId : uid;

        if (uid !== 'me' && req.user.role !== 'ROLE_ADMIN' && req.user.userId !== userId) 
            return res.status(403).json({ message: "Access denied. Requires admin role or be the account owner." });
        

        const user = await User.findById(userId);
        if (!user) 
            return res.status(404).json({ message: "No user found with the given UID" });
        

        res.status(200).json({
            uid: user._id,
            login: user.login,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error." });
    }
});

router.put('/account/:uid', isAuthenticated, async (req, res) => {
    const { uid } = req.params;
    const { login, password, role, status } = req.body;
    const userId = uid === 'me' ? req.user.userId : uid;

    try {
        if (uid !== 'me' && req.user.role !== 'ROLE_ADMIN' && req.user.userId !== userId)
            return res.status(403).json({ message: "Access denied. Requires admin role or ownership of the account." });

        const user = await User.findById(userId);
        if (!user)
            return res.status(404).json({ message: "User not found" });

        if (req.user.role === 'ROLE_ADMIN' && userId !== req.user.userId) {
            user.role = 'ROLE_ADMIN'; 
        } else {
            user.login = login || user.login;
            user.password = password ? await bcrypt.hash(password, 10) : user.password;
            user.role = role || user.role;
            user.status = status || user.status;
        }

        await user.save();

        res.status(201).json({
            uid: user._id,
            login: user.login,
            role: user.role,
            status: user.status,
            createdAt: user.createdAt,
            updatedAt: new Date()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error." });
    }
});

router.post('/token', loginLimiter, async (req, res) => {
    const { login, password } = req.body;

    try {
        const user = await User.findOne({ login });
        if (!user) 
            return res.status(401).json({ message: 'Login failed' });
        

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) 
            return res.status(401).json({ message: 'Login failed' });
        

        const accessToken = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '60m' });
        const refreshToken = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_REFRESH_SECRET, { expiresIn: '120m' });

        res.status(201).json({
            accessToken,
            accessTokenExpiresAt: new Date(Date.now() + 3600000).toISOString(),
            refreshToken,
            refreshTokenExpiresAt: new Date(Date.now() + 7200000).toISOString()
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error." });
    }
});

router.get('/validate/:accessToken', (req, res) => {
    const { accessToken } = req.params;

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);

        res.status(200).json({
            accessToken: accessToken,
            accessTokenExpiresAt: new Date(decoded.exp * 1000).toISOString()  // Convertir l'expiration en format ISO
        });

    } catch (error) {
        res.status(404).json({ message: "Token not found or invalid" });
    }
});

router.post('/refresh-token/:refreshToken/token', async (req, res) => {
    const { refreshToken } = req.params;

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const accessToken = jwt.sign(
            { userId: decoded.userId, role: decoded.role },
            process.env.JWT_SECRET,
            { expiresIn: '60m' }
        );

        const newRefreshToken = jwt.sign(
            { userId: decoded.userId, role: decoded.role },
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: '120m' }
        );

        res.status(201).json({
            accessToken: accessToken,
            accessTokenExpiresAt: new Date(Date.now() + 3600000).toISOString(),
            refreshToken: newRefreshToken,
            refreshTokenExpiresAt: new Date(Date.now() + 7200000).toISOString()
        });
    } catch (error) {
        res.status(404).json({ message: "Invalid or expired refresh token" });
    }
});

module.exports = router;