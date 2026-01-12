const NotificationModel = require('../models/Notification');

module.exports = {
  renderNotifications(req, res, notificationsStore) {
    const filter = (req.query.filter || 'all').toLowerCase();
    const user = req.session.user;
    const uid = user && (user.id || user.userId || user.ID);

    const allList = user && user.role === 'admin'
      ? NotificationModel.getNotificationsForAdmin(notificationsStore)
      : NotificationModel.getNotificationsForUser(notificationsStore, uid);

    let filtered = allList;
    if (filter === 'unread') {
      filtered = allList.filter(n => !n.read);
    } else if (filter === 'read') {
      filtered = allList.filter(n => n.read);
    }

    res.render('notifications', {
      user,
      notifications: filtered,
      filter,
      totalUnread: allList.filter(n => !n.read).length,
      errors: req.flash('error'),
      success: req.flash('success')
    });
  }
};
