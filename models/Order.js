// Lightweight Order model that works with the existing in-memory orders array
// defined in app.js. For now we accept the store as a parameter so this module
// does not create its own global state or DB connection.

module.exports = {
  getOrdersByUser(ordersStore, userId) {
    if (!userId) return [];
    return (ordersStore || []).filter(o => String(o.userId) === String(userId)).slice().reverse();
  },

  getAllOrders(ordersStore) {
    return (ordersStore || []).slice().reverse();
  },

  getOrderById(ordersStore, id) {
    if (!id) return null;
    return (ordersStore || []).find(o => String(o.id) === String(id)) || null;
  }
};
