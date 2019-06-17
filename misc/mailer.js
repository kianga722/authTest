const nodemailer = require('nodemailer');

// DOTENV
require('dotenv').config();

const transport = nodemailer.createTransport({
  service: 'SendGrid',
  auth: {
    user: process.env.sendgrid_user,
    pass: process.env.sendgrid_pass,
  },
});

module.exports = {
  sendEmail(from, to, subject, html) {
    return new Promise((resolve, reject) => {
      transport.sendMail({
        from, subject, to, html,
      }, (err, info) => {
        if (err) reject(err);

        resolve(info);
      });
    });
  },
};
