// Simple membership model focused on points and tiers.

module.exports = {
  getPointsFromUser(user) {
    return Number(user && user.points != null ? user.points : 0) || 0;
  }
};
