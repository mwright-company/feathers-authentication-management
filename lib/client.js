'use strict';

/* global module: 0 */
// Wrapper for client interface to feathers-authenticate-management

function AuthManagement(app) {
  // eslint-disable-line no-unused-vars
  if (!(this instanceof AuthManagement)) {
    return new AuthManagement(app);
  }

  var authManagement = app.service('authManagement');

  this.checkUnique = function (identifyUser, ownId, ifErrMsg, cb) {
    return authManagement.create({
      action: 'checkUnique',
      value: identifyUser,
      ownId: ownId,
      meta: { noErrMsg: ifErrMsg }
    }, {}, cb);
  };

  this.resendVerifySignup = function (identifyUser, notifierOptions, cb) {
    return authManagement.create({
      action: 'resendVerifySignup',
      value: identifyUser,
      notifierOptions: notifierOptions
    }, {}, cb);
  };

  this.verifySignupLong = function (verifyToken, cb) {
    return authManagement.create({
      action: 'verifySignupLong',
      value: verifyToken
    }, {}, cb);
  };

  this.verifySignupShort = function (verifyShortToken, identifyUser, cb) {
    return authManagement.create({
      action: 'verifySignupShort',
      value: { user: identifyUser, token: verifyShortToken }
    }, {}, cb);
  };

  this.sendResetPwd = function (identifyUser, notifierOptions, cb) {
    return authManagement.create({
      action: 'sendResetPwd',
      value: identifyUser,
      notifierOptions: notifierOptions
    }, {}, cb);
  };

  this.resetPwdLong = function (resetToken, password, cb) {
    return authManagement.create({
      action: 'resetPwdLong',
      value: { token: resetToken, password: password }
    }, {}, cb);
  };

  this.resetPwdShort = function (resetShortToken, identifyUser, password, cb) {
    return authManagement.create({
      action: 'resetPwdShort',
      value: { user: identifyUser, token: resetShortToken, password: password }
    }, {}, cb);
  };

  this.passwordChange = function (oldPassword, password, identifyUser, cb) {
    return authManagement.create({
      action: 'passwordChange',
      value: { user: identifyUser, oldPassword: oldPassword, password: password }
    }, {}, cb);
  };

  this.identityChange = function (password, changesIdentifyUser, identifyUser, cb) {
    return authManagement.create({
      action: 'identityChange',
      value: { user: identifyUser, password: password, changes: changesIdentifyUser }
    }, {}, cb);
  };

  this.authenticate = function (email, password, cb) {
    var cbCalled = false;

    return app.authenticate({ type: 'local', email: email, password: password }).then(function (result) {
      var user = result.data;

      if (!user || !user.isVerified) {
        app.logout();
        return cb(new Error(user ? 'User\'s email is not verified.' : 'No user returned.'));
      }

      if (cb) {
        cbCalled = true;
        return cb(null, user);
      }

      return user;
    }).catch(function (err) {
      if (!cbCalled) {
        cb(err);
      }
    });
  };
}

if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = AuthManagement;
}