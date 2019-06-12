const express = require('express');

const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const randomstring = require('randomstring');
const { ensureNotAuthenticated } = require('../config/auth');

const mailer = require('../misc/mailer');

// User model
const User = require('../models/User');

// Login Page
router.get('/login', (req, res) => {
  res.render('login');
});

// Register Page
router.get('/register', (req, res) => {
  res.render('register');
});

// Register Handle
router.post('/register', (req, res) => {
  const {
    name, email, password, password2,
  } = req.body;
  const errors = [];

  // Check required fields
  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please fill in all fields' });
  }

  // Check passwords match
  if (password !== password2) {
    errors.push({ mesg: 'Passwords do not match' });
  }

  // Check pass length
  if (password.length < 6) {
    errors.push({ msg: 'Password should be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2,
    });
  } else {
    // Validation passed
    User.findOne({ email })
      .then((user) => {
        if (user) {
          // User exists
          errors.push({ msg: 'Email is already registered' });
          res.render('register', {
            errors,
            name,
            email,
            password,
            password2,
          });
        } else {
          const newUser = new User({
            name,
            email,
            password,
          });

          // Hash Password
          bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            // Set password to hashed
            newUser.password = hash;

            // Set secret token
            const secretToken = randomstring.generate();
            newUser.secretToken = secretToken;

            // Flag the account as inactive
            newUser.active = false;

            // Save user
            newUser.save()
              .then((user) => {
                // Compose an email
                const html = `Hi there,
                  <br/>
                  THank you for registering!
                  <br/><br/>
                  Please verify your email by typing the following token:
                  <br/>
                  Token: <b>${secretToken}</b>
                  <br/>
                  On the following page:
                  <a href="http://localhost:5000/users/verify">http://localhost:5000/users/verify</a>
                  <br/><br/>
                  Have a pleasant day!`;

                // Send the email
                mailer.sendEmail('admin@spongebob.com', newUser.email, 'Please verify your email!', html);

                req.flash('success_msg', 'An activation e-mail has been sent to you. You must activate before you can log in');
                res.redirect('login');
              })
              .catch(err => console.log(err));
          }));
        }
      });
  }
});

// Verify Page
router.get('/verify', ensureNotAuthenticated, (req, res) => {
  res.render('verify');
});

router.post('/verify', (req, res) => {
  const { secretToken } = req.body;
  // Find the account that matches the secret token
  User.findOne({ secretToken })
    .then((user) => {
      if (!user) {
        req.flash('error_msg', 'No user found');
        res.redirect('/users/verify');
        return;
      }
      const userFound = user;
      userFound.active = true;
      userFound.secretToken = '';
      userFound.save()
        .then((userFound) => {
          req.flash('success_msg', 'E-mail confirmed. You may now login.');
          res.redirect('/users/login');
        })
        .catch(err => console.log(err));
    });
});

// Login Handle
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true,
  })(req, res, next);
});

// Logout Handle
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('login');
});

module.exports = router;
