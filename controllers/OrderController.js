const { estimateDeliveryDate } = require('../utils/orderUtils');

// In-memory orders are currently managed in app.js and persisted via store.json.
// This controller provides a tidy wrapper around that logic so routes can be
// gradually moved out of app.js without changing behaviour.

function getUserIdFromSessionUser(user) {
  if (!user) return null;
  return user.id || user.userId || user.ID || null;
}

module.exports = {
  // Return all orders for the current user (from in-memory store passed in).
  listUserOrders(req, res, ordersStore) {
    const uid = getUserIdFromSessionUser(req.session.user);
    const raw = (ordersStore || []).filter(o => String(o.userId) === String(uid));
    const safeOrders = raw.map(o => {
      const clone = { ...o };
      clone.estimatedDelivery = estimateDeliveryDate(clone.createdAt, clone.deliveryOption);
      return clone;
    });
    return res.render('orders', { orders: safeOrders, user: req.session.user });
  },

  // Render a single order detail for owner or admin.
  showOrderDetail(req, res, ordersStore) {
    const id = req.params.id;
    const uid = getUserIdFromSessionUser(req.session.user);
    const o = (ordersStore || []).find(x => String(x.id) === String(id));
    if (!o) return res.status(404).send('Order not found');
    if (String(o.userId) !== String(uid) && !(req.session.user && req.session.user.role === 'admin')) {
      return res.status(403).send('Access denied');
    }
    const clone = { ...o };
    clone.estimatedDelivery = estimateDeliveryDate(clone.createdAt, clone.deliveryOption);
    return res.render('order_detail', { order: clone, user: req.session.user });
  }
};
