const nodemailer = require('nodemailer');
const config = require('../config/mailer');

const transport = nodemailer.createTransport({
  service: 'SendGrid',
  auth: {
    user: config.SENDGRID_USER,
    pass: config.SENDGRID_PASS,
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
