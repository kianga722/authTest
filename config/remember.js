const User = require('../models/User');

module.exports = {
  consumeRememberToken(token, fn) {
    User.findOne({ tokenRemember: token })
      .then((user) => {
        if (user) {
          const userFound = user;
          userFound.tokenRemember = '';
          userFound.save()
            .then(userSaved => fn(null, user))
            .catch(err => console.log(err));
        }
        return fn(null, user);
      });
  },
  saveRememberToken(token, uid, fn) {
    User.findOne({ _id: uid })
      .then((user) => {
        if (user) {
          const userFound = user;
          userFound.tokenRemember = token;
          userFound.save()
            .then(userSaved => fn())
            .catch(err => console.log(err));
        }
      });
  },
};
