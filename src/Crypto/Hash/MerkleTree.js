const crypto = require("crypto")

exports.hashWith = function(algo) {
  return function(value) {
    return crypto
      .createHash(algo)
      .update(value)
      .digest("hex")
  }
}
