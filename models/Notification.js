// Small helper model around the in-memory notifications array used in app.js.

module.exports = {
  getNotificationsForAdmin(store) {
    return (store || []).filter(n => n.role === 'admin').slice().reverse();
  },

  getNotificationsForUser(store, userId) {
    if (!userId) return [];
    return (store || []).filter(n => n.role === 'user' && (!n.userId || String(n.userId) === String(userId))).slice().reverse();
  }
};
