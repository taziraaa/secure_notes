const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../config/db');

// Halaman login
router.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/notes/dashboard');
    res.render('login', { error: null });
});

// Proses login
router.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.render('login', { error: 'Email atau password salah!' });
        }
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('login', { error: 'Email atau password salah!' });
        }
        req.session.user = { id: user.id, username: user.username };
        res.redirect('/notes/dashboard');
    });
});

// Halaman register
router.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/notes/dashboard');
    res.render('register', { error: null });
});

// Proses register
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashedPassword],
        (err) => {
            if (err) {
                return res.render('register', { error: 'Email sudah terdaftar!' });
            }
            res.redirect('/auth/login');
        }
    );
});

// Logout
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/auth/login');
});

module.exports = router;