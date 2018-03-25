/*
 * Copyright (c) 2018-present Kriasoft | MIT License
 */

const pause = require('pause');
const cookie = require('cookie');
const jwt = require('jsonwebtoken');
const Strategy = require('passport-strategy');

class SessionStrategy extends Strategy {
  constructor(options) {
    super();
    this.name = 'session';
    this._name = options.name;
    this._secret = options.secret;
    this._audience = options.audience;
    this._issuer = options.issuer;
    this._findUser = options.findUser;
    this._createToken = options.createToken;
    this._deleteToken = options.deleteToken;
  }

  authenticate(req) {
    // Try to obtain a token from the session cookie
    let token = cookie.parse(req.headers.cookie || '')[this._name];

    if (token) {
      try {
        token = jwt.verify(token, this._secret, {
          audience: this._audience,
          issuer: this._issuer,
        });

        const paused = pause(req);
        Promise.resolve()
          .then(() => this._findUser(token))
          .then(user => {
            req.user = user;
            this.pass();
            paused.resume();
          })
          .catch(err => {
            this.error(err);
            paused.resume();
          });
      } catch (err) {
        if (err.name === 'TokenExpiredError') {
          try {
            token = jwt.verify(token, this._secret, {
              audience: this._audience,
              issuer: this._issuer,
              ignoreExpiration: true,
            });

            if (token) {
              const paused = pause(req);
              Promise.resolve()
                .then(() => this._findUser(token))
                .then(
                  user =>
                    user
                      ? Promise.resolve(this._deleteToken(token)).then(() =>
                          req.logIn(user),
                        )
                      : null,
                )
                .then(() => {
                  this.pass();
                  paused.resume();
                })
                .catch(userError => {
                  this.error(userError);
                  paused.resume();
                });
            }
          } catch (decodeError) {
            this.error(decodeError);
          }
        } else {
          this.error(err);
        }
      }
    } else {
      this.pass();
    }
  }
}

module.exports = SessionStrategy;
