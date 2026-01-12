// Controller to keep profile-related handlers tidy.

module.exports = {
  renderProfile(req, res, getUserById) {
    const sessionUser = req.session.user;
    getUserById(sessionUser.id, (err, dbUser) => {
      if (err || !dbUser) {
        console.error('Failed to load profile user:', err);
        req.flash('error', 'Could not load profile.');
        return res.redirect('/');
      }
      const formData = {
        username: dbUser.username,
        email: dbUser.email,
        address: dbUser.address,
        contact: dbUser.contact
      };
      res.render('profile', {
        user: dbUser,
        messages: req.flash('success'),
        errors: req.flash('error'),
        formData,
        passwordStep: req.session.passwordStep || 'start',
        otpHint: req.session.passwordOtpHint || null
      });
    });
  }
};
