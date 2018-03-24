/*
 * Copyright (c) 2018-present Kriasoft | MIT License
 */

const uuid = require('uuid');
const initialize = require('./initialize');
const authenticate = require('./authenticate');

const users = new Map();
const tokens = new Map();

/**
 * Initializes Passport.js framework that uses JWT for sessions.
 */
exports = module.exports = (options = {}) => ({
  options: Object.assign(
    {
      name: '__session',
      expiresIn: '1 hour',
      createToken(req) {
        return {
          sub: req.user.id,
          jti: uuid.v4(),
          login_ip: req.ip,
        };
      },
      findUser(token) {
        return users.get(token.sub);
      },
      saveToken(token) {
        tokens.set(token.jti, token.sub);
      },
      deleteToken(token) {
        tokens.delete(token.jti);
      },
    },
    options,
    {
      cookie: Object.assign(
        {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 60 * 60 * 24 * 365 * 10 /* 10 years */,
        },
        options.cookie,
      ),
    },
  ),
  initialize,
  authenticate,
});

module.exports();
