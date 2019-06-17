// const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const randomstring = require('randomstring');

const LocalStrategy = require('passport-local').Strategy;
const RememberMeStrategy = require('passport-remember-me').Strategy;

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
            return done(null, false, { message: 'Invalid E-mail address' });
          }

          // Match password
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;

            if (isMatch) {
              // If user account has not been verified
              if (!user.active) {
                return done(null, false, { message: 'Please verify your account by e-mail first.' });
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

  passport.use(
    new RememberMeStrategy(
      async (token, done) => {
        const userFound = await User.findOne({ tokenRemember: token });
        if (userFound) {
          userFound.tokenRemember = undefined;
          await userFound.save();
          await done(null, userFound);
          return;
        }
        await done(null, userFound);
      },
      async (user, done) => {
        const token = randomstring.generate();
        const userFound = await User.findOne({ _id: user._id });
        if (userFound) {
          userFound.tokenRemember = token;
          await userFound.save();
          await done(null, token);
          return;
        }
        await done(null, token);
      },
    ),
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
