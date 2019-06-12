const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Load User Model
const User = require('../models/User');

module.exports = function (passport) {
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
      // Match User
      User.findOne({ email })
        .then((user) => {
          // Check if email already exists
          if (!user) {
            return done(null, false, { message: 'That email is not registered' });
          }

          // Match password
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;

            if (isMatch) {
              // If user account has not been verified
              if (!user.active) {
                return done(null, false, { message: 'Please verify your account by e-mail first' });
              }
              // Account verified
              return done(null, user);
            }
            // Incorrect password
            return done(null, false, { message: 'Password incorrect' });
          });
        })
        .catch(err => console.log(err));
    }),
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });
};
