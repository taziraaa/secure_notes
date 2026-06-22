const express = require('express');
const router = express.Router();
const db = require('../config/db');
const aes256 = require('../utils/aes256'); // implementasi AES-256-CBC manual (tanpa library AES)
require('dotenv').config();

const SECRET_KEY = Buffer.from(process.env.AES_SECRET_KEY); // harus 32 byte untuk AES-256

// Fungsi enkripsi (memanggil implementasi AES-256-CBC manual)
function encrypt(text) {
    return aes256.encrypt(text, SECRET_KEY); // -> { ciphertext, iv }
}

// Fungsi dekripsi (memanggil implementasi AES-256-CBC manual)
function decrypt(ciphertext, ivHex) {
    return aes256.decrypt(ciphertext, ivHex, SECRET_KEY);
}

// Middleware cek login
function requireLogin(req, res, next) {
    console.log('Session user:', req.session.user);
    if (!req.session.user) return res.redirect('/auth/login');
    next();
}
// Dashboard
router.get('/dashboard', requireLogin, (req, res) => {
    db.query('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC',
        [req.session.user.id],
        (err, results) => {
            const notes = results.map(note => ({
                ...note,
                content: decrypt(note.content, note.iv)
            }));
            res.render('dashboard', { user: req.session.user, notes });
        }
    );
});

// Halaman tambah catatan
router.get('/add', requireLogin, (req, res) => {
    const filePath = require('path').join(__dirname, '../views/add-note.ejs');
    const ejs = require('ejs');
    ejs.renderFile(filePath, { user: req.session.user }, (err, html) => {
        if (err) {
            console.error('EJS Error:', err);
            return res.status(500).send('EJS Error: ' + err.message);
        }
        res.send(html);
    });
});
// Proses tambah catatan
router.post('/add', requireLogin, (req, res) => {
    const { title, content } = req.body;
    const { ciphertext, iv } = encrypt(content);
    db.query('INSERT INTO notes (user_id, title, content, iv) VALUES (?, ?, ?, ?)',
        [req.session.user.id, title, ciphertext, iv],
        (err) => {
            if (err) console.error(err);
            res.redirect('/notes/dashboard');
        }
    );
});

// Halaman edit catatan
router.get('/edit/:id', requireLogin, (req, res) => {
    db.query('SELECT * FROM notes WHERE id = ? AND user_id = ?',
        [req.params.id, req.session.user.id],
        (err, results) => {
            if (results.length === 0) return res.redirect('/notes/dashboard');
            const note = results[0];
            note.content = decrypt(note.content, note.iv);
            res.render('edit-note', { user: req.session.user, note });
        }
    );
});

// Proses edit catatan
router.post('/edit/:id', requireLogin, (req, res) => {
    const { title, content } = req.body;
    const { ciphertext, iv } = encrypt(content);
    db.query('UPDATE notes SET title = ?, content = ?, iv = ? WHERE id = ? AND user_id = ?',
        [title, ciphertext, iv, req.params.id, req.session.user.id],
        (err) => {
            if (err) console.error(err);
            res.redirect('/notes/dashboard');
        }
    );
});

// Hapus catatan
router.post('/delete/:id', requireLogin, (req, res) => {
    db.query('DELETE FROM notes WHERE id = ? AND user_id = ?',
        [req.params.id, req.session.user.id],
        (err) => {
            if (err) console.error(err);
            res.redirect('/notes/dashboard');
        }
    );
});

module.exports = router;