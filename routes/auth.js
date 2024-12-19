const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const authenticateToken = require('../middleware/auth');

const router = express.Router();


// Register endpoint
router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
       

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insert user into database
        const [result] = await db.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Login endpoint




router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];

        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Validate password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

        

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});



router.get('/profile',authenticateToken, async (req, res) => {

    try {
        const [users] = await db.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});



module.exports = router;
