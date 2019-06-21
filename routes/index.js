const express = require('express');

const router = express.Router();
const passport = require('passport');
const { ensureAuthenticated, ensureNotAuthenticated } = require('../config/auth');

// Welcome Page
/*
router.get('/', ensureNotAuthenticated, (req, res) => {
  res.render('welcome');
});
*/
router.get('/', (req, res, next) => {
  passport.authenticate('jwt', { session: false },
    (err, user, info) => {
      if (err) { return next(err); }
      if (!user) { return res.render('welcome'); }
      return res.redirect('dashboard');
    })(req, res, next);
});

// Dashboard
/*
router.get('/dashboard', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.render('dashboard', {
    name: req.user.name,
  });
});
*/
router.get('/dashboard', (req, res, next) => {
  passport.authenticate('jwt', { session: false },
    (err, user, info) => {
      if (err) { return next(err); }
      if (!user) { return res.render('login'); }
      return res.render('dashboard', {
        name: user.name,
      });
    })(req, res, next);
});

module.exports = router;
