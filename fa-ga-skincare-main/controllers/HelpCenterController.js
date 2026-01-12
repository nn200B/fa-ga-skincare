const HelpRequestModel = require('../models/HelpRequest');

module.exports = {
  renderUserHelpCenter(req, res, orders, getUserIdFromSessionUser, addNotification, inMemory) {
    const userId = getUserIdFromSessionUser(req.session.user);
    const allOrders = (orders || []).filter(o => String(o.userId) === String(userId));
    const eligibleAddressOrders = allOrders.filter(o => {
      const status = (o.deliveryStatus || '').toLowerCase();
      return status === 'packed' || status === 'item packed';
    });
    const refundableOrders = allOrders.filter(o => (o.status || '').toLowerCase() === 'paid');
    const errors = req.flash('error');
    const success = req.flash('success');
    res.render('help_center', {
      user: req.session.user,
      eligibleAddressOrders,
      refundableOrders,
      errors,
      success
    });
  },

  renderAdminHelpCenter(req, res, inMemory) {
    const refunds = HelpRequestModel.getAllRefunds(inMemory.refundRequests);
    const addressChanges = HelpRequestModel.getAllAddressChanges(inMemory.addressChangeRequests);
    res.render('admin_help_center', {
      user: req.session.user,
      refunds: refunds || [],
      addressChanges: addressChanges || [],
      errors: req.flash('error'),
      success: req.flash('success')
    });
  }
};
