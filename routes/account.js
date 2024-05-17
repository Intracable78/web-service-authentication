const express = require('express');
const User = require('../models/user');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const verifyAdmin = require('../middlewares/verifyAdmin');
const isAuthenticated = require('../middlewares/isAuthenticate');


/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - login
 *         - password
 *         - role
 *         - status
 *       properties:
 *         login:
 *           type: string
 *         password:
 *           type: string
 *           description: Le mot de passe de l'utilisateur, doit être hashé avant d'être stocké
 *         role:
 *           type: string
 *         status:
 *           type: string
 *         created_at:
 *           type: string
 *           format: date-time
 *       example:
 *         login: userAdmin
 *         password: password123
 *         role: ROLE_ADMIN
 *         status: open
 *         created_at: 2023-01-01T00:00:00.000Z
 */

/**
 * @swagger
 * /account:
 *   post:
 *     summary: Créer un nouvel utilisateur
 *     tags: [User]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: Utilisateur créé avec succès
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 uid:
 *                   type: string
 *                 login:
 *                   type: string
 *                 role:
 *                   type: string
 *                 status:
 *                   type: string
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *       409:
 *         description: Utilisateur déjà existant
 *       500:
 *         description: Erreur serveur
 */

router.post('/account', async (req, res) => {
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

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     BearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         uid:
 *           type: string
 *         login:
 *           type: string
 *         roles:
 *           type: array
 *           items:
 *             type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /account/{uid}:
 *   get:
 *     summary: Récupérer les informations d'un utilisateur par UID
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: uid
 *         schema:
 *           type: string
 *         required: true
 *         description: UID de l'utilisateur ou 'me' pour l'utilisateur courant
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Informations de l'utilisateur récupérées avec succès
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       403:
 *         description: Accès refusé. Nécessite un rôle admin ou être le propriétaire du compte
 *       404:
 *         description: Aucun utilisateur trouvé avec l'UID donné
 *       500:
 *         description: Erreur serveur
 */

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

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     BearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         uid:
 *           type: string
 *         login:
 *           type: string
 *         roles:
 *           type: array
 *           items:
 *             type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *     UpdateUser:
 *       type: object
 *       properties:
 *         login:
 *           type: string
 *         password:
 *           type: string
 *         role:
 *           type: string
 *         status:
 *           type: string
 *       example:
 *         login: user123
 *         password: password123
 *         role: admin
 *         status: active
 */

/**
 * @swagger
 * /account/{uid}:
 *   put:
 *     summary: Mettre à jour les informations d'un utilisateur par UID
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: uid
 *         schema:
 *           type: string
 *         required: true
 *         description: UID de l'utilisateur ou 'me' pour l'utilisateur courant
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUser'
 *     responses:
 *       201:
 *         description: Informations de l'utilisateur mises à jour avec succès
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       403:
 *         description: Accès refusé. Nécessite un rôle admin ou être le propriétaire du compte
 *       404:
 *         description: Utilisateur non trouvé
 *       500:
 *         description: Erreur serveur
 */

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

/**
 * @swagger
 * components:
 *   schemas:
 *     TokenResponse:
 *       type: object
 *       properties:
 *         accessToken:
 *           type: string
 *         accessTokenExpiresAt:
 *           type: string
 *           format: date-time
 *         refreshToken:
 *           type: string
 *         refreshTokenExpiresAt:
 *           type: string
 *           format: date-time
 *       example:
 *         accessToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         accessTokenExpiresAt: 2023-01-01T00:00:00.000Z
 *         refreshToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         refreshTokenExpiresAt: 2023-01-01T02:00:00.000Z
 * 
 * /token:
 *   post:
 *     summary: Authentifier un utilisateur et obtenir des tokens
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               login:
 *                 type: string
 *               password:
 *                 type: string
 *             example:
 *               login: userAdmin
 *               password: password123
 *     responses:
 *       201:
 *         description: Authentification réussie, tokens générés
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       401:
 *         description: Échec de l'authentification
 *       500:
 *         description: Erreur serveur
 */

router.post('/token',  async (req, res) => {
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

/**
 * @swagger
 * components:
 *   schemas:
 *     TokenValidationResponse:
 *       type: object
 *       properties:
 *         accessToken:
 *           type: string
 *         accessTokenExpiresAt:
 *           type: string
 *           format: date-time
 *       example:
 *         accessToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         accessTokenExpiresAt: 2023-01-01T00:00:00.000Z
 */

/**
 * @swagger
 * /validate/{accessToken}:
 *   get:
 *     summary: Valider un access token
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: accessToken
 *         schema:
 *           type: string
 *         required: true
 *         description: Le token JWT à valider
 *     responses:
 *       200:
 *         description: Token validé avec succès
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenValidationResponse'
 *       404:
 *         description: Token non trouvé ou invalide
 */

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

/**
 * @swagger
 * components:
 *   schemas:
 *     TokenResponse:
 *       type: object
 *       properties:
 *         accessToken:
 *           type: string
 *         accessTokenExpiresAt:
 *           type: string
 *           format: date-time
 *         refreshToken:
 *           type: string
 *         refreshTokenExpiresAt:
 *           type: string
 *           format: date-time
 *       example:
 *         accessToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         accessTokenExpiresAt: 2023-01-01T00:00:00.000Z
 *         refreshToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         refreshTokenExpiresAt: 2023-01-01T02:00:00.000Z
 */

/**
 * @swagger
 * /refresh-token/{refreshToken}/token:
 *   post:
 *     summary: Générer un nouveau access token et refresh token
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: refreshToken
 *         schema:
 *           type: string
 *         required: true
 *         description: Le refresh token JWT à valider
 *     responses:
 *       201:
 *         description: Tokens générés avec succès
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       404:
 *         description: Refresh token invalide ou expiré
 */

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