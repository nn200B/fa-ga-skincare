// Model wrapper for refund and address-change requests stored in memory.

module.exports = {
  getAllRefunds(store) {
    return (store || []).slice().reverse();
  },

  getAllAddressChanges(store) {
    return (store || []).slice().reverse();
  }
};
