const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  tokenEmail: {
    type: String,
  },
  tokenEmailExpires: {
    type: Date,
  },
  active: {
    type: Boolean,
  },
  tokenRemember: {
    type: String,
  },
  tokenForgot: {
    type: String,
  },
  tokenForgotExpires: {
    type: Date,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model('User', UserSchema);

module.exports = User;
