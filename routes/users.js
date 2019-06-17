const express = require('express');

const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const randomstring = require('randomstring');

// Authenticated methods
const { ensureAuthenticated, ensureNotAuthenticated } = require('../config/auth');

const mailer = require('../misc/mailer');

// User model
const User = require('../models/User');

// Login Page
router.get('/login', ensureNotAuthenticated, (req, res) => {
  res.render('login');
});

// Register Page
router.get('/register', ensureNotAuthenticated, (req, res) => {
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
    errors.push({ msg: 'Passwords do not match' });
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

            // Set activation token
            const tokenEmail = randomstring.generate();
            newUser.tokenEmail = tokenEmail;
            newUser.tokenEmailExpires = Date.now() + 60000;

            // Flag the account as inactive
            newUser.active = false;

            // Save user
            newUser.save()
              .then((user) => {
                // Compose an email
                const html = `Hi there,
                  <br/>
                  Thank you for registering!
                  <br/><br/>
                  Please verify your email by clicking the following link:
                  <br/>
                  <a href="http://${req.headers.host}/users/verify/${tokenEmail}">http://${req.headers.host}/users/verify/${tokenEmail}</a>
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

// Verify Email Page
router.get('/verify/:token', ensureNotAuthenticated, (req, res) => {
  const tokenEmail = req.params.token;
  if (tokenEmail === '' || tokenEmail === undefined) {
    req.flash('error_msg', 'Activation link is invalid or has expired');
    res.redirect('/users/resend');
    return;
  }

  // Find the account that matches the secret token
  User.findOne({
    tokenEmail,
    tokenEmailExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        req.flash('error_msg', 'Activation link is invalid or has expired');
        res.redirect('/users/resend');
        return;
      }
      const userFound = user;
      userFound.active = true;
      userFound.tokenEmail = undefined;
      userFound.tokenEmailExpires = undefined;
      userFound.save()
        .then((userFound) => {
          req.login(user, (err) => {
            if (err) {
              console.log(err);
            }
            req.flash('success_msg', `E-mail confirmed. Welcome ${user.name}!`);
            res.redirect('/dashboard');
          });
        })
        .catch(err => console.log(err));
    });
});

// Resend Activation Email Page
router.get('/resend', ensureNotAuthenticated, (req, res) => {
  res.render('resend');
});

router.post('/resend', (req, res) => {
  const { email } = req.body;

  User.findOne({ email })
    .then((user) => {
      // If no user found
      if (!user) {
        req.flash('error_msg', 'Email is invalid');
        res.redirect('resend');
        return;
      }

      // If user already active
      if (user.active) {
        req.flash('error_msg', 'User already active!');
        res.redirect('resend');
        return;
      }

      // Set new secret token
      const tokenEmail = randomstring.generate();
      const userNew = user;
      userNew.tokenEmail = tokenEmail;
      userNew.tokenEmailExpires = Date.now() + 60000;

      // Save user with new token
      userNew.save()
        .then((userFound) => {
          // Compose an email
          const html = `Hi there,
            <br/>
            We are resending your activation email.
            <br/><br/>
            Please verify your email by clicking the following link:
            <br/>
            <a href="http://${req.headers.host}/users/verify/${tokenEmail}">http://${req.headers.host}/users/verify/${tokenEmail}</a>
            <br/><br/>
            Have a pleasant day!`;
          // Send the email with new token
          mailer.sendEmail('admin@spongebob.com', userFound.email, 'Activation email resend request', html);

          req.flash('success_msg', `Another activation e-mail has been sent to ${userFound.email}`);
          res.redirect('resend');
        })
        .catch(err => console.log(err));
    });
});

// Forgot Password Page
router.get('/forgot', ensureNotAuthenticated, (req, res) => {
  res.render('forgot');
});

router.post('/forgot', (req, res) => {
  const { email } = req.body;

  User.findOne({ email })
    .then((user) => {
      // If no user found
      if (!user) {
        req.flash('error_msg', 'Email is invalid');
        res.redirect('forgot');
        return;
      }

      // Set new secret token
      const tokenForgot = randomstring.generate();
      const userNew = user;
      userNew.tokenForgot = tokenForgot;
      userNew.tokenForgotExpires = Date.now() + 60000;

      // Save user with new token
      userNew.save()
        .then((userFound) => {
          // Compose an email
          const html = `Hi there,
            <br/>
            You are receiving this because you (or someone else) has requested the reset of the password for your account.
            <br/><br/>
            Please click the following link to complete the process
            <br/>
            <a href="http://${req.headers.host}/users/reset/${tokenForgot}">http://${req.headers.host}/users/reset/${tokenForgot}</a>
            <br/><br/>
            If you id not request this, please ignore this email and your password will remain unchanged.`;
          // Send the email with new token
          mailer.sendEmail('admin@spongebob.com', userFound.email, 'Password Reset Request', html);

          req.flash('success_msg', `A password reset e-mail has been sent to ${userFound.email}`);
          res.redirect('forgot');
        })
        .catch(err => console.log(err));
    });
});

// Reset Password Page
router.get('/reset/:token', ensureNotAuthenticated, (req, res) => {
  const tokenForgot = req.params.token;
  if (tokenForgot === '' || tokenForgot === undefined) {
    req.flash('error_msg', 'Password Reset link is invalid or has expired');
    res.redirect('/users/forgot');
    return;
  }

  // Find the account that matches the secret token
  User.findOne({
    tokenForgot,
    tokenForgotExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        req.flash('error_msg', 'Password Reset link is invalid or has expired');
        res.redirect('/users/forgot');
        return;
      }
      res.render('reset', {
        email: user.email,
        tokenForgot,
      });
    });
});

router.post('/reset/:token', (req, res) => {
  const tokenForgot = req.params.token;
  // Check if token still valid
  User.findOne({
    tokenForgot,
    tokenForgotExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (!user) {
        req.flash('error_msg', 'Password Reset link is invalid or has expired');
        res.redirect('/users/forgot');
        return;
      }
      // If token is valid
      const {
        email,
        password,
        password2,
      } = req.body;
      const errors = [];

      // Check required fields
      if (!password || !password2) {
        errors.push({ msg: 'Please fill in all fields' });
      }

      // Check passwords match
      if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
      }

      // Check pass length
      if (password.length < 6) {
        errors.push({ msg: 'Password should be at least 6 characters' });
      }

      if (errors.length > 0) {
        res.render('reset', {
          email,
          tokenForgot,
          errors,
        });
      } else {
        // Validation passed

        // Hash Password
        bcrypt.genSalt(10, (err, salt) => bcrypt.hash(password, salt, (err, hash) => {
          if (err) throw err;

          const userEdit = user;
          // Remove reset token
          userEdit.tokenForgot = undefined;
          userEdit.tokenForgotExpires = undefined;
          // Set password to hashed
          userEdit.password = hash;

          // Save user
          userEdit.save()
            .then((user) => {
              // Compose an email
              const html = `Hi there,
                <br/>
                This is a confirmation that the password for your account ${userEdit.email} has just been changed.
                <br/><br/>
                Have a pleasant day!`;
              // Send the email
              mailer.sendEmail('admin@spongebob.com', userEdit.email, 'Your password has been changed', html);

              req.flash('success_msg', 'Success! Your password has been changed.');
              res.redirect('/users/login');
            })
            .catch(err => console.log(err));
        }));
      }
    });
});

// Login Handle
router.post('/login',
  passport.authenticate('local', {
    failureRedirect: '/users/login',
    failureFlash: true,
  }),
  (req, res, next) => {
    // Issue a remember me cookie if the option was checked
    if (!req.body.remember) { return next(); }

    const token = randomstring.generate();

    User.findOne({ _id: req.user._id })
      .then((user) => {
        if (user) {
          const userFound = user;
          userFound.tokenRemember = token;
          userFound.save()
            .then((userSaved) => {
              res.cookie('remember_me', token, { path: '/', httpOnly: true, maxAge: 604800000 }); // 7 days
              return next();
            })
            .catch(err => console.log(err));
        }
      });
  },
  (req, res) => {
    res.redirect('/dashboard');
  });

// Logout Handle
router.get('/logout', ensureAuthenticated, (req, res) => {
  // clear the remember me cookie when logging out
  res.clearCookie('remember_me');

  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('login');
});

module.exports = router;
