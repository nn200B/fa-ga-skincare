// Shared order-related helper functions extracted from app.js so that both
// routes and controllers can reuse the same behaviour.

function addBusinessDays(date, days) {
  const d = new Date(date);
  let added = 0;
  while (added < days) {
    d.setDate(d.getDate() + 1);
    const day = d.getDay(); // 0 Sun, 6 Sat
    if (day !== 0 && day !== 6) added++;
  }
  return d;
}

function estimateDeliveryDate(createdAtIso, deliveryOption) {
  try {
    const created = new Date(createdAtIso || new Date().toISOString());
    if (deliveryOption === 'one-day') {
      return addBusinessDays(created, 1).toISOString();
    }
    return addBusinessDays(created, 3).toISOString();
  } catch (e) {
    return new Date().toISOString();
  }
}

module.exports = { addBusinessDays, estimateDeliveryDate };
