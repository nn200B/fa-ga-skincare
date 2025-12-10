const db = require('../db');

/**
 * User model (function-based)
 * Table: users
 * Columns (assumed): id (PK), email, password, role
 * Node-style callbacks: callback(err, result)
 */

module.exports = {
  createUser: function(user, callback) {
    // user: { email, password, role }
    const sql = 'INSERT INTO users (email, password, role) VALUES (?, ?, ?)';
    db.query(sql, [user.email, user.password, user.role || 'customer'], function(err, result) {
      return callback(err, result);
    });
  },

  getUserByEmail: function(email, callback) {
    const sql = 'SELECT * FROM users WHERE email = ? LIMIT 1';
    db.query(sql, [email], function(err, results) {
      if (err) return callback(err);
      return callback(null, results && results.length ? results[0] : null);
    });
  },

  getUserById: function(id, callback) {
    const sql = 'SELECT * FROM users WHERE id = ? LIMIT 1';
    db.query(sql, [id], function(err, results) {
      if (err) return callback(err);
      return callback(null, results && results.length ? results[0] : null);
    });
  },

  updateUser: function(id, user, callback) {
    // user: { email, password, role }
    const sql = 'UPDATE users SET email = ?, password = ?, role = ? WHERE id = ?';
    db.query(sql, [user.email, user.password, user.role, id], function(err, result) {
      return callback(err, result);
    });
  },

  deleteUser: function(id, callback) {
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [id], function(err, result) {
      return callback(err, result);
    });
  }
};
