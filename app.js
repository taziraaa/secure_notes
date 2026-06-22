require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.set('views', __dirname);
app.set('view engine', 'ejs');

const authRoutes = require('./auth');
const notesRoutes = require('./notes');

app.use('/auth', authRoutes);
app.use('/notes', notesRoutes);

app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/notes/dashboard');
    } else {
        res.redirect('/auth/login');
    }
});

const PORT = process.env.PORT || 8080;
app.use((err, req, res, next) => {
    console.error('ERROR:', err.message);
    res.status(500).send('Error: ' + err.message);
});
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
