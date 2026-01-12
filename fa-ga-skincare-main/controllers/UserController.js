const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Republic_C207',
  database: 'c372_glowaura_skincare'
});

module.exports = {
  register(req, res) {
    const { username, email, password, address, contact, role } = req.body || {};
    if (!username || !email || !password) return res.status(400).render('register', { error: 'Required fields missing' });
    const sql = 'INSERT INTO users (username, email, password, address, contact, role) VALUES (?, ?, SHA1(?), ?, ?, ?)';
    connection.query(sql, [username, email, password, address, contact, role], (err, result) => {
      if (err) return res.status(500).render('register', { error: 'Registration failed' });
      if (req.session) req.session.user = { id: result.insertId, username, email, role };
      req.flash('success', 'Registration successful');
      return res.redirect('/');
    });
  },

  login(req, res) {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).render('login', { error: 'Required fields missing' });
    const sql = 'SELECT * FROM users WHERE email = ? AND password = SHA1(?)';
    connection.query(sql, [email, password], (err, results) => {
      if (err) return res.status(500).render('login', { error: 'Login failed' });
      if (!results || results.length === 0) return res.status(401).render('login', { error: 'Invalid credentials' });
      const user = results[0];
      if (req.session) req.session.user = user;
      req.flash('success', 'Login successful');
      if (user.role === 'admin') return res.redirect('/inventory');
      return res.redirect('/shopping');
    });
  },

  logout(req, res) {
    if (req.session) {
      req.session.destroy(() => res.redirect('/'));
      return;
    }
    return res.redirect('/');
  },

  checkAuth(req, res, next) {
    if (req.session && req.session.user) return next();
    req.flash('error', 'Please log in');
    return res.redirect('/login');
  },

  checkAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') return next();
    req.flash('error', 'Admin access required');
    return res.redirect('/');
  }
};
