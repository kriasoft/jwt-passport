# Passport.js framework that uses JWT for sessions

> This is an alternative framework for Passport.js that is designed to use JWT
> tokens for sessions. So that, instead of storing user's ID and metadata in a
> database (e.g. Redis), it encodes that data into a JSON Web Token and writes
> that token to a session cookie.

## How to Install

```bash
$ npm install jwt-passport
```

_**Note**: It requires Node.js 6.11 or higher_

## How to Use

```js
const uuid = require('uuid');
const express = require('express');
const passport = require('passport');
const jwt = require('jwt-passport');

// We're using Knex.js database client in this examle,
// but it could be any other database driver.
const db = require('./db');

passport.framework(
  jwt({
    name: '__session',
    secret: '<secret>',
    audience: '<autidence>',
    issuer: '<issuer>',
    expiresIn: '1 hour',

    // Prepare the payload for a JWT token
    createToken: req => ({
      sub: req.user.id,
      jti: uuid.v4(),
    }),

    // Save user's token in a database
    saveToken: token =>
      db
        .table('user_tokens')
        .insert({
          user_id: token.sub,
          token_id: token.jti,
        }),

    // Revoke user's token
    deleteToken: token =>
      db
        .table('user_tokens')
        .where({ token_id: token.jti })
        .del(),

    // Check if the token was not revoked and find the corresponding user
    findUser: token =>
      db
        .table('user_tokens')
        .leftJoin('users', 'users.id', 'user_tokens.user_id')
        .where({ 'user_tokens.token_id': token.jti })
        .select('users.*')
        .first(),
  });
);

passport.use(new FacebookStrategy(/* config */));
passport.use(new TwitterStrategy(/* config */));

const app = express();

// Extend the HTTP request object with
// req.logIn() and req.logOut() helper methods
app.use(passport.initialize());

// Attemp to parse session cookie, validate the token
// and put the authenticated user object onto the contxt (req.user)
app.use(passport.session());

app.get('/', (req, res) => {
  res.send(`Welcome, ${req.user ? req.user.displayName : 'guest'}!`);
});

app.get('/login/:provider', (req, res, next) => {
  passport.authenticate(req.params.provider, /* options */)(req, res, next);
});

app.get('/login/:provider/return', (req, res, next) => {
  passport.authenticate(req.params.provider, /* options */)(req, res, next);
});
```

## Related Projects

* [Node.js API Starter][nsk] — Boilerplate for authoring GraphQL APIs with Node.js and PostgreSQL
* [React Starter Kit][rsk] — Boilerpalte for authoring isomorphic web apps with React.js and GraphQL
* [React Starter Kit for Firebase][rskfb] — React.js web app boilerplate for serveless architecture

## License

Copyright © 2018-present Kriasoft. This source code is licensed under the MIT
[license][lic].

[nsk]: https://github.com/kriasoft/nodejs-api-starter
[rsk]: https://github.com/kriasoft/react-starter-kit
[rskfb]: https://github.com/kriasoft/react-firebase-starter
[lic]: https://github.com/kriasoft/jwt-passport/blob/master/LICENSE
