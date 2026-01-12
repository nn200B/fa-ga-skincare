const CategoryModel = require('../models/Category');

module.exports = {
  renderUserCategories(req, res, categoriesStore) {
    const categories = CategoryModel.getAllFromMemory(categoriesStore).map(c => c);
    return res.render('categories_user', { categories, user: req.session.user });
  },

  renderAdminCategories(req, res, categoriesStore, productsStore) {
    const categories = CategoryModel.getAllFromMemory(categoriesStore);
    const products = (productsStore || []).slice();
    const grouped = categories.map(c => {
      const items = products.filter(p => (p.category || '') === c.name);
      return { category: c, products: items };
    });
    res.render('categories', { user: req.session.user, groupedCategories: grouped });
  }
};
