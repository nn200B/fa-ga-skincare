// Category model built on top of existing helpers/structures.

module.exports = {
  getAllFromMemory(categoriesStore) {
    return (categoriesStore || []).slice();
  }
};
