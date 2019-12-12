'use strict';

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

/* eslint-env node */

var errors = require('feathers-errors');
var debug = require('debug')('authManagement:resetPassword');

var _require = require('./helpers'),
    getUserData = _require.getUserData,
    ensureObjPropsValid = _require.ensureObjPropsValid,
    ensureValuesAreStrings = _require.ensureValuesAreStrings,
    sanitizeUserForClient = _require.sanitizeUserForClient,
    hashPassword = _require.hashPassword,
    notifier = _require.notifier;

module.exports.resetPwdWithLongToken = function (options, resetToken, password) {
  return Promise.resolve().then(function () {
    ensureValuesAreStrings(resetToken, password);

    return resetPassword(options, { resetToken: resetToken }, { resetToken: resetToken }, password);
  });
};

module.exports.resetPwdWithShortToken = function (options, resetShortToken, identifyUser, password) {
  return Promise.resolve().then(function () {
    ensureValuesAreStrings(resetShortToken, password);
    ensureObjPropsValid(identifyUser, options.identifyUserProps);

    return resetPassword(options, identifyUser, { resetShortToken: resetShortToken }, password);
  });
};

function resetPassword(options, query, tokens, password) {
  debug('resetPassword', query, tokens, password);
  var users = options.app.service(options.service);
  var usersIdName = users.id;

  return Promise.all([users.find({ query: query }).then(function (data) {
    return getUserData(data, ['isVerified', 'resetNotExpired']);
  }), hashPassword(options.app, password)]).then(function (_ref) {
    var _ref2 = _slicedToArray(_ref, 2),
        user = _ref2[0],
        hashedPassword = _ref2[1];

    if (!Object.keys(tokens).every(function (key) {
      return tokens[key] === user[key];
    })) {
      return patchUser(user, {
        resetToken: null,
        resetShortToken: null,
        resetExpires: null
      }).then(function () {
        throw new errors.BadRequest('Invalid token. Get for a new one. (authManagement)', { errors: { $className: 'badParam' } });
      });
    }

    return patchUser(user, {
      password: hashedPassword,
      resetToken: null,
      resetShortToken: null,
      resetExpires: null
    }).then(function (user1) {
      return notifier(options.notifier, 'resetPwd', user1);
    }).then(function (user1) {
      return sanitizeUserForClient(user1);
    });
  });

  function patchUser(user, patchToUser) {
    return users.patch(user[usersIdName], patchToUser, {}) // needs users from closure
    .then(function () {
      return Object.assign(user, patchToUser);
    });
  }
}