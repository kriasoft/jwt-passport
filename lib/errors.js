/*
 * Copyright (c) 2018-present Kriasoft | MIT License
 */

class AuthenticationError extends Error {
  constructor(message, status) {
    super(message);
    Error.captureStackTrace(this, this.constructor);
    this.name = this.constructor.name;
    this.status = status || 401;
  }
}

module.exports.AuthenticationError = AuthenticationError;
