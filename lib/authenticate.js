/*
 * Copyright (c) 2011-2015 Jared Hanson | MIT License
 * Copyright (c) 2018-present Kriasoft | MIT License
 */

const http = require('http');
const { AuthenticationError } = require('./errors');

module.exports = function authenticateFn(passport, name, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  options = options || {};

  let multi = true;

  if (!Array.isArray(name)) {
    name = [name];
    multi = false;
  }

  return function authenticate(req, res, next) {
    // accumulator for failures from each strategy in the chain
    const failures = [];

    function allFailed() {
      if (callback) {
        if (!multi) {
          return callback(
            null,
            false,
            failures[0].challenge,
            failures[0].status,
          );
        } else {
          const challenges = failures.map(x => x.challenge);
          const statuses = failures.map(x => x.status);
          return callback(null, false, challenges, statuses);
        }
      }

      // Strategies are ordered by priority.  For the purpose of flashing a
      // message, the first failure will be displayed.
      let failure = failures[0] || {};
      let challenge = failure.challenge || {};
      let msg;

      if (options.failureFlash) {
        let flash = options.failureFlash;
        if (typeof flash === 'string') {
          flash = { type: 'error', message: flash };
        }
        flash.type = flash.type || 'error';

        const type = flash.type || challenge.type || 'error';
        msg = flash.message || challenge.message || challenge;
        if (typeof msg === 'string') {
          req.flash(type, msg);
        }
      }
      if (options.failureMessage) {
        msg = options.failureMessage;
        if (typeof msg === 'boolean') {
          msg = challenge.message || challenge;
        }
        if (typeof msg === 'string') {
          req.session.messages = req.session.messages || [];
          req.session.messages.push(msg);
        }
      }
      if (options.failureRedirect) {
        return res.redirect(options.failureRedirect);
      }

      // When failure handling is not delegated to the application, the default
      // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
      // header will be set according to the strategies in use (see
      // actions#fail).  If multiple strategies failed, each of their challenges
      // will be included in the response.
      const rchallenge = [];
      let rstatus;
      let status;

      for (let j = 0, len = failures.length; j < len; j++) {
        failure = failures[j];
        ({ challenge } = failure);
        ({ status } = failure);

        rstatus = rstatus || status;
        if (typeof challenge === 'string') {
          rchallenge.push(challenge);
        }
      }

      res.statusCode = rstatus || 401;
      if (res.statusCode === 401 && rchallenge.length) {
        res.setHeader('WWW-Authenticate', rchallenge);
      }
      if (options.failWithError) {
        return next(
          new AuthenticationError(http.STATUS_CODES[res.statusCode], rstatus),
        );
      }
      res.end(http.STATUS_CODES[res.statusCode]);
    }

    (function attempt(i) {
      const layer = name[i];
      // If no more strategies exist in the chain, authentication has failed.
      if (!layer) {
        return allFailed();
      }

      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      const prototype = passport._strategy(layer);
      if (!prototype) {
        return next(new Error(`Unknown authentication strategy "${layer}".`));
      }

      const strategy = Object.create(prototype);

      // ----- BEGIN STRATEGY AUGMENTATION -----
      // Augment the new strategy instance with action functions.  These action
      // functions are bound via closure the the request/response pair.  The end
      // goal of the strategy is to invoke *one* of these action methods, in
      // order to indicate successful or failed authentication, redirect to a
      // third-party identity provider, etc.

      /**
       * Authenticate `user`, with optional `info`.
       *
       * Strategies should call this function to successfully authenticate a
       * user.  `user` should be an object supplied by the application after it
       * has been given an opportunity to verify credentials.  `info` is an
       * optional argument containing additional user information.  This is
       * useful for third-party authentication strategies to pass profile
       * details.
       *
       * @param {Object} user
       * @param {Object} info
       * @api public
       */
      strategy.success = function success(user, info) {
        if (callback) {
          return callback(null, user, info);
        }

        info = info || {};
        let msg;

        if (options.successFlash) {
          let flash = options.successFlash;
          if (typeof flash == 'string') {
            flash = { type: 'success', message: flash };
          }
          flash.type = flash.type || 'success';

          const type = flash.type || info.type || 'success';
          msg = flash.message || info.message || info;
          if (typeof msg === 'string') {
            req.flash(type, msg);
          }
        }
        if (options.successMessage) {
          msg = options.successMessage;
          if (typeof msg === 'boolean') {
            msg = info.message || info;
          }
          if (typeof msg === 'string') {
            req.session.messages = req.session.messages || [];
            req.session.messages.push(msg);
          }
        }
        if (options.assignProperty) {
          req[options.assignProperty] = user;
          return next();
        }

        req
          .logIn(user)
          .then(
            () =>
              options.authInfo !== false &&
              new Promise((resolve, reject) => {
                passport.transformAuthInfo(info, req, (err, tinfo) => {
                  if (err) {
                    return reject(err);
                  } else {
                    req.authInfo = tinfo;
                    resolve();
                  }
                });
              }),
          )
          .then(() => {
            if (options.successReturnToOrRedirect) {
              let url = options.successReturnToOrRedirect;
              if (req.session && req.session.returnTo) {
                url = req.session.returnTo;
                delete req.session.returnTo;
              }
              return res.redirect(url);
            }
            if (options.successRedirect) {
              return res.redirect(options.successRedirect);
            }
            next();
          })
          .catch(next);
      };

      /**
       * Fail authentication, with optional `challenge` and `status`, defaulting
       * to 401.
       *
       * Strategies should call this function to fail an authentication attempt.
       *
       * @param {String} challenge
       * @param {Number} status
       * @api public
       */
      strategy.fail = function fail(challenge, status) {
        if (typeof challenge === 'number') {
          status = challenge;
          challenge = undefined;
        }

        // push this failure into the accumulator and attempt authentication
        // using the next strategy
        failures.push({ challenge, status });
        attempt(i + 1);
      };

      /**
       * Redirect to `url` with optional `status`, defaulting to 302.
       *
       * Strategies should call this function to redirect the user (via their
       * user agent) to a third-party website for authentication.
       *
       * @param {String} url
       * @param {Number} status
       * @api public
       */
      strategy.redirect = function redirect(url, status) {
        // NOTE: Do not use `res.redirect` from Express, because it can't decide
        //       what it wants.
        //
        //       Express 2.x: res.redirect(url, status)
        //       Express 3.x: res.redirect(status, url) -OR- res.redirect(url, status)
        //         - as of 3.14.0, deprecated warnings are issued if res.redirect(url, status)
        //           is used
        //       Express 4.x: res.redirect(status, url)
        //         - all versions (as of 4.8.7) continue to accept res.redirect(url, status)
        //           but issue deprecated versions

        res.statusCode = status || 302;
        res.setHeader('Location', url);
        res.setHeader('Content-Length', '0');
        res.end();
      };

      /**
       * Pass without making a success or fail decision.
       *
       * Under most circumstances, Strategies should not need to call this
       * function.  It exists primarily to allow previous authentication state
       * to be restored, for example from an HTTP session.
       *
       * @api public
       */
      strategy.pass = function pass() {
        next();
      };

      /**
       * Internal error while performing authentication.
       *
       * Strategies should call this function when an internal error occurs
       * during the process of performing authentication; for example, if the
       * user directory is not available.
       *
       * @param {Error} err
       * @api public
       */
      strategy.error = function error(err) {
        if (callback) {
          return callback(err);
        }

        next(err);
      };

      // ----- END STRATEGY AUGMENTATION -----

      strategy.authenticate(req, options);
    })(0); // attempt
  };
};
