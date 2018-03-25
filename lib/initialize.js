/*
 * Copyright (c) 2018-present Kriasoft | MIT License
 */

const cookie = require('cookie');
const jwt = require('jsonwebtoken');
const SessionStrategy = require('./session');

module.exports = function initizlizeFn(passport) {
  const { options } = this;

  passport.use(new SessionStrategy(options));

  return function initialize(req, res, next) {
    /**
     * Creates a persistent session for the user.
     *
     * @param {User} user
     * @api public
     */
    req.logIn = function logIn(user) {
      req.user = user;

      const token = jwt.sign(
        Object.assign(
          {},
          options.audience && { aud: options.audience },
          options.issuer && { iss: options.issuer },
          options.createToken(req),
        ),
        options.secret,
      );

      return Promise.resolve()
        .then(() => options.saveToken(jwt.decode(token)))
        .then(() => {
          res.cookie(options.name, token, options.cookie);
        });
    };

    /**
     * Removes user's session.
     *
     * @api public
     */
    req.logOut = function logOut() {
      req.user = null;
      res.clearCookie(options.name, options.cookie);

      let token = cookie.parse(req.headers.cookie || '')[options.name];

      if (token) {
        try {
          token = jwt.decode(token);
        } catch (err) {
          return Promise.reject(err);
        }
      }

      return token
        ? Promise.resolve().then(() => options.deleteToken(token))
        : Promise.resolve();
    };

    req.isAuthenticated = () => !!req.user;
    req.isUnauthenticated = () => !req.user;

    next();
  };
};
