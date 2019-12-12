'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

/* eslint no-param-reassign: 0 */

var errors = require('feathers-errors');
var utils = require('feathers-hooks-common/lib/utils');

var _require = require('./helpers'),
    getLongToken = _require.getLongToken,
    getShortToken = _require.getShortToken;

module.exports.addVerification = function (path) {
  return function (hook) {
    utils.checkContext(hook, 'before', 'create');

    return Promise.resolve().then(function () {
      return hook.app.service(path || 'authManagement').create({ action: 'options' });
    }).then(function (options) {
      return Promise.all([options, getLongToken(options.longTokenLen), getShortToken(options.shortTokenLen, options.shortTokenDigits)]);
    }).then(function (_ref) {
      var _ref2 = _slicedToArray(_ref, 3),
          options = _ref2[0],
          longToken = _ref2[1],
          shortToken = _ref2[2];

      hook.data.isVerified = false;
      hook.data.verifyExpires = Date.now() + options.delay;
      hook.data.verifyToken = longToken;
      hook.data.verifyShortToken = shortToken;
      hook.data.verifyChanges = {};

      return hook;
    }).catch(function (err) {
      throw new errors.GeneralError(err);
    });
  };
};

module.exports.isVerified = function () {
  return function (hook) {
    utils.checkContext(hook, 'before');

    if (!hook.params.user || !hook.params.user.isVerified) {
      throw new errors.BadRequest('User\'s email is not yet verified.');
    }
  };
};

module.exports.removeVerification = function (ifReturnTokens) {
  return function (hook) {
    utils.checkContext(hook, 'after');
    var user = hook.result || {};

    if (!('isVerified' in user) && hook.method === 'create') {
      /* eslint-disable no-console */
      console.warn('Property isVerified not found in user properties. (removeVerification)');
      console.warn('Have you added authManagement\'s properties to your model? (Refer to README.md)');
      console.warn('Have you added the addVerification hook on users::create?');
      /* eslint-enable */
    }

    if (hook.params.provider && user) {
      // noop if initiated by server
      delete user.verifyExpires;
      delete user.resetExpires;
      delete user.verifyChanges;
      if (!ifReturnTokens) {
        delete user.verifyToken;
        delete user.verifyShortToken;
        delete user.resetToken;
        delete user.resetShortToken;
      }
    }
  };
};